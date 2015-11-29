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
	ID               int64             `json:"id"`
	Timestamp        time.Time         `json:"timestamp"`
	Target           string            `json:"target"`
	Replay           int               `json:"replay"` //hours or days
	Has_tls          bool              `json:"has_tls"`
	Cert_id          int64             `json:"cert_id"`
	Trust_id         int64             `json:"trust_id"`
	Is_valid         bool              `json:"is_valid"`
	Validation_error string            `json:"validation_error,omitempty"`
	Complperc        int               `json:"completion_perc"`
	Conn_info        connection.Stored `json:"connection_info"`
	Ack              bool
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

func (db *DB) NewScan(domain string, rplay int) (Scan, error) {

	timestamp := time.Now()

	var id int64

	err := db.QueryRow("INSERT INTO scans (timestamp,target,replay,has_tls,is_valid,completion_perc,validation_error,conn_info,ack) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id", timestamp, domain, rplay, false, false, 0, "", []byte("null"), false).Scan(&id)

	if err != nil {
		return Scan{}, err
	}

	return Scan{ID: id, Timestamp: timestamp, Replay: rplay}, nil
}

func (db *DB) GetScanByID(id int64) (Scan, error) {

	s := Scan{}
	s.ID = id

	var cID, tID sql.NullInt64

	var isvalid sql.NullBool

	var ci []byte

	row := db.QueryRow(`SELECT timestamp, target, replay, has_tls, cert_id, trust_id,
	is_valid, completion_perc, validation_error, conn_info, ack FROM scans WHERE id=$1`, id)

	err := row.Scan(&s.Timestamp, &s.Target, &s.Replay, &s.Has_tls, &cID, &tID,
		&isvalid, &s.Complperc, &s.Validation_error, &ci, &s.Ack)

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

	return s, err
}

func (db *DB) UpdateScanCompletionPercentage(id int64, p int) error {
	_, err := db.Exec("UPDATE scans SET completion_perc=$1 WHERE id=$2", p, id)

	return err
}

func (db *DB) InsertWorkerAnalysis(scanid int64, jsonRes []byte, workerName string) error {
	_, err := db.Exec("INSERT INTO analysis(scan_id,worker_name,	output) VALUES($1,$2,$3)", scanid, workerName, jsonRes)

	return err
}
