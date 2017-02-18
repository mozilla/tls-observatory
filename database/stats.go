package database

import "time"

// CountTableEntries returns the estimated count of scans, trusts relationships, analyses
// and certificates stored in database. The count uses Postgres' own stats counter and is
// not guaranteed to be fully accurate.
func (db *DB) CountTableEntries() (scans, trusts, analyses, certificates int64, err error) {
	err = db.QueryRow(`SELECT reltuples::INTEGER FROM pg_class WHERE relname='scans'`).Scan(&scans)
	if err != nil {
		return
	}
	err = db.QueryRow(`SELECT reltuples::INTEGER FROM pg_class WHERE relname='trust'`).Scan(&trusts)
	if err != nil {
		return
	}
	err = db.QueryRow(`SELECT reltuples::INTEGER FROM pg_class WHERE relname='analysis'`).Scan(&analyses)
	if err != nil {
		return
	}
	err = db.QueryRow(`SELECT reltuples::INTEGER FROM pg_class WHERE relname='certificates'`).Scan(&certificates)
	if err != nil {
		return
	}
	return
}

// CountPendingScans returns the total number of scans that are pending in the queue
func (db *DB) CountPendingScans() (count int64, err error) {
	err = db.QueryRow(`SELECT COUNT(*) FROM scans
				  WHERE completion_perc = 0
				  AND attempts < 3 AND ack = false`).Scan(&count)
	return
}

// HourlyScansCount represents the number of scans completed over one hour
type HourlyScansCount struct {
	Hour  time.Time `json:"hour"`
	Count int64     `json:"count"`
}

// CountLast24HoursScans returns a list of hourly scans count for the last 24 hours, sorted
// from most recent the oldest
func (db *DB) CountLast24HoursScans() (hourlyStats []HourlyScansCount, err error) {
	rows, err := db.Query(`SELECT DATE_TRUNC('hour', "timestamp") AS hour, COUNT(*) 
				     FROM scans
				     WHERE timestamp > NOW() - INTERVAL '24 hours' AND ack=true AND completion_perc=100
				     GROUP BY DATE_TRUNC('hour', "timestamp") ORDER BY 1 DESC`)
	if err != nil {
		return
	}
	for rows.Next() {
		var hsc HourlyScansCount
		err = rows.Scan(&hsc.Hour, &hsc.Count)
		if err != nil {
			return
		}
		hourlyStats = append(hourlyStats, hsc)
	}
	return
}

// CountDistinctTargetsLast24Hours returns the number of unique targets scanned over the last 24 hours
func (db *DB) CountDistinctTargetsLast24Hours() (count int64, err error) {
	err = db.QueryRow(`SELECT COUNT(DISTINCT(target))
				  FROM scans
				  WHERE timestamp > NOW() - INTERVAL '24 hours'
				  AND ack=true
				  AND completion_perc=100`).Scan(&count)
	return
}

// CountDistinctCertsSeenLast24Hours returns the count of unique certificates seen over the last 24 hours
func (db *DB) CountDistinctCertsSeenLast24Hours() (count int64, err error) {
	err = db.QueryRow(`SELECT COUNT(DISTINCT(id))
				  FROM certificates
				  WHERE last_seen > NOW() - INTERVAL '24 hours'`).Scan(&count)
	return
}

// CountDistinctCertsAddedLast24Hours returns the count of unique certificates added over the last 24 hours
func (db *DB) CountDistinctCertsAddedLast24Hours() (count int64, err error) {
	err = db.QueryRow(`SELECT COUNT(DISTINCT(id))
				  FROM certificates
				  WHERE first_seen > NOW() - INTERVAL '24 hours'`).Scan(&count)
	return
}
