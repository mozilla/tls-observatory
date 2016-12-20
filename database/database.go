package database

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	_ "github.com/lib/pq"

	"github.com/mozilla/tls-observatory/connection"
)

type DB struct {
	*sql.DB
}

type Scan struct {
	ID               int64                  `json:"id"`
	Timestamp        time.Time              `json:"timestamp"`
	Target           string                 `json:"target"`
	Replay           int                    `json:"replay"` //hours or days
	Has_tls          bool                   `json:"has_tls"`
	Cert_id          int64                  `json:"cert_id"`
	Trust_id         int64                  `json:"trust_id"`
	Is_valid         bool                   `json:"is_valid"`
	Validation_error string                 `json:"validation_error,omitempty"`
	Complperc        int                    `json:"completion_perc"`
	Conn_info        connection.Stored      `json:"connection_info"`
	AnalysisResults  Analyses               `json:"analysis,omitempty"`
	Ack              bool                   `json:"ack"`
	Attempts         int                    `json:"attempts"` //number of retries
	AnalysisParams   map[string]interface{} `json:"analysis_params"`
}

type Analysis struct {
	ID       int64           `json:"id"`
	Analyzer string          `json:"analyzer"`
	Result   json.RawMessage `json:"result"`
	Success  bool            `json:"success"`
}

type Analyses []Analysis

// Methods used for the sorting of analyses

func (slice Analyses) Len() int {
	return len(slice)
}

func (slice Analyses) Less(i, j int) bool {
	return slice[i].Analyzer < slice[j].Analyzer
}

func (slice Analyses) Swap(i, j int) {
	slice[i], slice[j] = slice[j], slice[i]
}

func RegisterConnection(dbname, user, password, hostport, sslmode string) (*DB, error) {

	url := fmt.Sprintf("postgres://%s:%s@%s/%s?sslmode=%s",
		user, password, hostport, dbname, sslmode)

	db, err := sql.Open("postgres", url)

	if err != nil {
		db = nil
	}

	return &DB{db}, err
}

func (db *DB) NewScan(domain string, rplay int, jsonParams []byte) (Scan, error) {
	timestamp := time.Now().UTC()

	var id int64

	err := db.QueryRow(`INSERT INTO scans
			(timestamp, target, replay, has_tls, is_valid, completion_perc, validation_error, conn_info, ack, attempts, analysis_params)
			VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
			RETURNING id`,
		timestamp, domain, rplay, false, false, 0, "", []byte("null"), false, 1, jsonParams).Scan(&id)

	if err != nil {
		return Scan{}, err
	}

	return Scan{ID: id, Timestamp: timestamp, Replay: rplay}, nil
}

// GetLastScanTimeForTarget searches the database for the latest scan for a specific target.
// It returns both the scan timestamp and the id of the scan to enable the api to
// respond to clients with just one db query.
func (db *DB) GetLastScanTimeForTarget(target string) (int64, time.Time, error) {

	var (
		id int64
		t  time.Time
	)

	row := db.QueryRow(`SELECT id, timestamp
			    FROM scans
			    WHERE target=$1 ORDER BY timestamp DESC LIMIT 1`, target)

	err := row.Scan(&id, &t)

	if err != nil {
		if err == sql.ErrNoRows {
			return -1, time.Now(), nil
		} else {
			return -1, time.Now(), err
		}
	}
	return id, t, nil
}

func (db *DB) GetScanByID(id int64) (Scan, error) {

	s := Scan{}
	s.ID = id

	var cID, tID sql.NullInt64

	var isvalid sql.NullBool

	var ci []byte
	var params []byte

	row := db.QueryRow(`SELECT timestamp, target, replay, has_tls, cert_id, trust_id,
				   is_valid, completion_perc, validation_error, conn_info, ack, attempts, analysis_params
			    FROM scans
			    WHERE id=$1`, id)

	err := row.Scan(&s.Timestamp, &s.Target, &s.Replay, &s.Has_tls, &cID, &tID,
		&isvalid, &s.Complperc, &s.Validation_error, &ci, &s.Ack, &s.Attempts, &params)

	if err != nil {
		if err == sql.ErrNoRows {
			s.ID = -1
			return s, nil
		} else {
			return s, err
		}
	}

	if cID.Valid {
		s.Cert_id = cID.Int64

	} else {
		s.Cert_id = -1
	}

	if tID.Valid {
		s.Trust_id = tID.Int64
	} else {
		s.Trust_id = -1
	}

	if isvalid.Valid {
		s.Is_valid = isvalid.Bool
	} else {
		s.Is_valid = false
	}

	err = json.Unmarshal(ci, &s.Conn_info)
	if err != nil {
		return s, err
	}

	err = json.Unmarshal(params, &s.AnalysisParams)
	if err != nil {
		return s, err
	}

	if s.Complperc > 40 {
		s.AnalysisResults, err = db.GetAnalysisByScan(s.ID)
		return s, err
	}

	return s, nil
}

func (db *DB) GetAnalysisByScan(id int64) ([]Analysis, error) {

	var ana []Analysis
	rows, err := db.Query("SELECT id,worker_name,output,success FROM analysis WHERE scan_id=$1", id)
	if err != nil {
		return ana, err
	}
	defer rows.Close()
	for rows.Next() {
		a := Analysis{}
		if err := rows.Scan(&a.ID, &a.Analyzer, &a.Result, &a.Success); err != nil {
			return ana, err
		}
		ana = append(ana, a)
	}
	return ana, nil
}

func (db *DB) UpdateScanCompletionPercentage(id int64, p int) error {
	_, err := db.Exec("UPDATE scans SET completion_perc=$1 WHERE id=$2", p, id)

	return err
}

func (db *DB) InsertWorkerAnalysis(scanid int64, jsonRes []byte, workerName string) error {
	_, err := db.Exec("INSERT INTO analysis(scan_id,worker_name,output) VALUES($1,$2,$3)", scanid, workerName, jsonRes)

	return err
}
