package postgresmodule

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/lib/pq"
)

//using latest https://hub.docker.com/_/postgres/ image for testing

type DB struct {
	*sql.DB
}

type Scan struct {
	id               int64
	time_stamp       time.Time
	Target           string
	replay           int //hours or days
	has_tls          bool
	cert_id          int
	trust_id         int
	is_valid         bool
	validation_error string
	complperc        int
	conn_info        []byte
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

	var ID int64

	err := db.QueryRow("INSERT INTO scans (timestamp,target,replay) VALUES($1,$2,$3) RETURNING id", timestamp, domain, rplay).Scan(&ID)

	if err != nil {
		return Scan{}, err
	}

	return Scan{id: ID, time_stamp: timestamp, replay: rplay}, nil
}

func (db *DB) GetScan(id int64) (Scan, error) {

	s := Scan{}
	s.id = id

	row := db.QueryRow(`SELECT time_stamp, target, replay, has_tls, 	cert_id,
	is_valid, completion_perc, validation_error, is_ubuntu_valid, is_mozilla_valid,
	is_windows_valid, is_apple_valid, conn_info
	FROM certificates WHERE id=$1`, id)

	err := row.Scan(&s.time_stamp, &s.Target, &s.replay, &s.has_tls, &s.cert_id,
		&s.is_valid, &s.validation_error, &s.conn_info)

	if err != nil {
		return s, err
	}

	return s, nil

}

func (db *DB) UpdateCompletionPercentage(id string, p int) error {
	_, err := db.Exec("UPDATE scans SET completion_perc=$1 WHERE id=$2", p, id)

	return err
}

func (db *DB) InsertWorkerAnalysis(scanid int64, jsonRes []byte, workerName string) error {
	_, err := db.Exec("INSERT INTO analysis(scan_id,worker_name,	output) VALUES($1,$2,$3)", scanid, workerName, jsonRes)

	return err
}
