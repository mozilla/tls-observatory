package postgresmodule

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "github.com/lib/pq"
)

const separator = "--"

//using latest https://hub.docker.com/_/postgres/ image for testing

type DB struct {
	*sql.DB
}

type Scan struct {
	ID               int64
	Timestamp        time.Time
	Target           string
	Replay           int //hours or days
	Has_tls          bool
	Cert_id          int64
	Trust_id         int64
	Is_valid         bool
	Validation_error string
	Complperc        int
	Conn_info        []byte
}

func RegisterConnection(dbname, user, password, hostport string, sslmode string) (*DB, error) {

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

	err := db.QueryRow("INSERT INTO scans (timestamp,target,replay,has_tls,is_valid,completion_perc,validation_error,conn_info) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id", timestamp, domain, rplay, false, false, 0, "", []byte("null")).Scan(&id)

	if err != nil {
		return Scan{}, err
	}

	return Scan{ID: id, Timestamp: timestamp, Replay: rplay}, nil
}

func (db *DB) GetScan(id int64) (Scan, error) {

	s := Scan{}
	s.ID = id

	var cID, tID sql.NullInt64

	var isvalid sql.NullBool

	row := db.QueryRow(`SELECT timestamp, target, replay, has_tls, cert_id, trust_id,
	is_valid, completion_perc, validation_error, conn_info
	FROM scans WHERE id=$1`, id)

	err := row.Scan(&s.Timestamp, &s.Target, &s.Replay, &s.Has_tls, &cID, &tID,
		&isvalid, &s.Complperc, &s.Validation_error, &s.Conn_info)

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

func StringSliceToString(slice []string) string {

	res := ""

	for _, s := range slice {
		if res == "" {
			res = s
		} else {
			res = res + separator + s
		}
	}

	return res

}

func StringToStringSlice(s string) []string {

	return strings.Split(s, separator)

}
