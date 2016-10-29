package database

import (
	"fmt"
	"strconv"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/lib/pq"

	"github.com/mozilla/tls-observatory/logger"
)

// RegisterScanListener "subscribes" to the notifications published to the scan_listener notifier.
// It has as input the usual db attributes and returns an int64 channel which can be consumed
// for newly created scan id's.
func (db *DB) RegisterScanListener(dbname, user, password, hostport, sslmode string) <-chan int64 {

	log := logger.GetLogger()

	reportProblem := func(ev pq.ListenerEventType, err error) {
		if err != nil {
			log.WithFields(logrus.Fields{
				"error": err.Error(),
			}).Error("Listener Error")
		}
	}

	listenerChan := make(chan int64)
	listenerName := "scan_listener"

	connInfo := fmt.Sprintf("postgres://%s:%s@%s/%s?sslmode=%s",
		user, password, hostport, dbname, sslmode)

	go func() {

		listener := pq.NewListener(connInfo, 100*time.Millisecond, 10*time.Second, reportProblem)
		err := listener.Listen(listenerName)

		if err != nil {
			log.WithFields(logrus.Fields{
				"listener": listenerName,
				"error":    err.Error(),
			}).Error("could not listen for notification")
			close(listenerChan)
			return
		}

		for m := range listener.Notify {
			sid := m.Extra
			if !db.acquireScan(sid) {
				// skip this scan if we didn't acquire it
				continue
			}
			// scan was acquired, inform the scanner to launch it
			id, err := strconv.ParseInt(string(sid), 10, 64)
			if err != nil {
				log.WithFields(logrus.Fields{
					"scan_id": sid,
					"error":   err.Error(),
				}).Error("could not decode acquired notification")
			}
			listenerChan <- id
			log.WithFields(logrus.Fields{
				"scan_id": id,
			}).Debug("Acquired notification.")
		}

	}()

	// Launch a goroutine that relaunches scans that have not yet been processed
	go func() {
		for {
			// don't requeue scans more than 3 times
			_, err := db.Exec(`UPDATE scans SET ack = false, timestamp = NOW()
				             WHERE completion_perc = 0 AND attempts < 3 AND ack = true
						   AND timestamp < NOW() - INTERVAL '10 minute'`)
			if err != nil {
				log.WithFields(logrus.Fields{
					"error": err,
				}).Error("Could not run zero completion update query")
			}
			_, err = db.Exec(fmt.Sprintf(`SELECT pg_notify('%s', ''||id )
						      FROM scans
						      WHERE ack=false
						      ORDER BY id ASC
						      LIMIT 1000`, listenerName))
			if err != nil {
				log.WithFields(logrus.Fields{
					"error": err,
				}).Error("Could not run unacknowledged scans periodic check.")
			}
			time.Sleep(3 * time.Minute)
		}
	}()
	return listenerChan
}

// acquireScan provides a way to limit to one the number of scanners
// evaluating a given target, but setting a `ack` boolean to true when a
// scanner picks up a scan
func (db *DB) acquireScan(id string) bool {
	tx, err := db.Begin()
	if err != nil {
		return false
	}
	// `ack` is a mutex in the database that each scanner will try to select
	// for update. if a scanner succeeds, it will return true, otherwise it
	// will return false.
	row := tx.QueryRow("SELECT ack FROM scans WHERE id=$1 FOR UPDATE", id)
	ack := false
	err = row.Scan(&ack)
	if err != nil {
		tx.Rollback()
		return false
	}
	if ack {
		// if ack was true in db, that means another job already acked this
		// scan so we drop the lock and return false
		tx.Rollback()
		return false
	}
	// otherwise, ack is false and we acquire it to run the scan
	// if anything fails along the way, we drop the lock by rolling back
	_, err = tx.Exec("UPDATE scans SET ack=true WHERE id=$1", id)
	if err != nil {
		tx.Rollback()
		return false
	}
	err = tx.Commit()
	if err != nil {
		tx.Rollback()
		return false
	}
	return true
}
