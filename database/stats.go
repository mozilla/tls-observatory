package database

import "time"

// Statistics is a set of counters maintained in the database
type Statistics struct {
	Scans                         int64              `json:"scans"`
	Trusts                        int64              `json:"trusts"`
	Analyses                      int64              `json:"analyses"`
	Certificates                  int64              `json:"certificates"`
	PendingScans                  int64              `json:"pendingScansCount"`
	Last24HoursScans              []HourlyScansCount `json:"last24HoursScansCount"`
	TargetsLast24Hours            int64              `json:"targetsLast24Hours"`
	DistinctTargetsLast24Hours    int64              `json:"distinctTargetsLast24Hours"`
	DistinctCertsSeenLast24Hours  int64              `json:"distinctCertsSeenLast24Hours"`
	DistinctCertsAddedLast24Hours int64              `json:"distinctCertsAddedLast24Hours"`
	ScansLast24Hours              int64              `json:"scansLast24Hours"`
}

// GetLatestStatisticsFromView retrieves the content of the `statistics` materialized view
// and returns it in a Statistics struct. The freshness of the data is not guaranteed, but if
// the materialized view is older than 5 minutes, an automatic refresh is kicked off *after*
// retrieving the data. In effect, unless you query the stats endpoint constantly, this will
// likely return data several minutes, if not a few hours old.
func (db *DB) GetLatestStatisticsFromView() (stats Statistics, err error) {
	var ts time.Time
	err = db.QueryRow(`SELECT timestamp, total_scans, total_trust, total_analysis, total_certificates,
					count_targets_last24h, count_distinct_targets_last24h, count_certificates_seen_last24h,
					count_certificates_added_last24h, count_scans_last24h, pending_scans
				FROM statistics`).Scan(&ts, &stats.Scans, &stats.Trusts, &stats.Analyses,
		&stats.Certificates, &stats.TargetsLast24Hours, &stats.DistinctTargetsLast24Hours,
		&stats.DistinctCertsSeenLast24Hours, &stats.DistinctCertsAddedLast24Hours,
		&stats.ScansLast24Hours, &stats.PendingScans)
	if ts.Before(time.Now().Add(-(5 * time.Minute))) {
		go db.Exec(`REFRESH MATERIALIZED VIEW CONCURRENTLY statistics`)
	}
	return
}

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

// CountTargetsLast24Hours returns the number of unique targets scanned over the last 24 hours
func (db *DB) CountTargetsLast24Hours() (count, countDistinct int64, err error) {
	err = db.QueryRow(`SELECT COUNT(target), COUNT(DISTINCT(target))
				  FROM scans
				  WHERE timestamp > NOW() - INTERVAL '24 hours'
				  AND ack=true
				  AND completion_perc=100`).Scan(&count, &countDistinct)
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

// CountScansLast24Hours returns the count of scans over the last 24 hours
func (db *DB) CountScansLast24Hours() (count int64, err error) {
	err = db.QueryRow(`SELECT COUNT(id)
				  FROM scans
				  WHERE timestamp > NOW() - INTERVAL '24 hours'
				  AND ack=true
				  AND completion_perc=100`).Scan(&count)
	return
}
