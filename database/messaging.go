package database

import (
	"fmt"
	"strconv"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/lib/pq"

	"github.com/mozilla/tls-observatory/logger"
)

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

	conn_info := fmt.Sprintf("postgres://%s:%s@%s/%s?sslmode=%s",
		user, password, hostport, dbname, sslmode)

	go func() {

		listener_name := "scan_listener"

		listener := pq.NewListener(conn_info, 100*time.Millisecond, 10*time.Second, reportProblem)
		err := listener.Listen(listener_name)

		if err != nil {
			log.WithFields(logrus.Fields{
				"listener": listener_name,
				"error":    err.Error(),
			}).Error("could not listen for notification")
			close(listenerChan)
			return
		}

		for m := range listener.Notify {
			sid := m.Extra
			if db.acquireNotification(sid) {

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
		}

	}()

	return listenerChan
}

func (db *DB) acquireNotification(id string) bool {

	tx, err := db.Begin()

	if err != nil {
		return false
	}

	r := tx.QueryRow("SELECT ack FROM scans WHERE id=$1 FOR UPDATE", id)

	var ack bool

	err = r.Scan(&ack)

	if err != nil {
		tx.Rollback()
		return false
	}

	if !ack {

		_, err = tx.Exec("UPDATE scans SET ack=$1 WHERE id=$2", true, id)
		if err != nil {
			tx.Rollback()
			return false
		}

		err = tx.Commit()

		if err != nil {
			tx.Rollback()
			return false
		} else {
			return true
		}
	} else {
		tx.Rollback()
		return false
	}
}
