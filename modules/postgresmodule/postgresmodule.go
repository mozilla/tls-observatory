package postgresmodule

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/lib/pq"
)

type DB struct {
	*sql.DB
}

type Scan struct {
	id               string
	time_stamp       time.Time
	Target           string
	replay           int //hours or days
	has_tls          bool
	cert_id          string
	is_valid         bool
	validation_error string
	is_ubuntu_valid  bool
	is_mozilla_valid bool
	is_windows_valid bool
	is_apple_valid   bool
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

	res, err := db.Exec("INSERT INTO scans (timestamp,target,replay) VALUES($1,$2,$3)", timestamp, domain, rplay)

	if err != nil {
		return Scan{}, err
	}

	ID, err := res.LastInsertId()

	if err != nil {
		return Scan{}, err
	}

	return Scan{id: fmt.Sprintf("%d", ID), time_stamp: timestamp, replay: rplay}, nil
}

func (db *DB) GetScan(id string) (Scan, error) {

	s := Scan{}
	s.id = id

	row := db.QueryRow(`SELECT time_stamp, target, replay, has_tls, 	cert_id,
	is_valid, completion_perc, validation_error, is_ubuntu_valid, is_mozilla_valid,
	is_windows_valid, is_apple_valid, conn_info
	FROM certificates WHERE id=$1`, id)

	err := row.Scan(&s.time_stamp, &s.Target, &s.replay, &s.has_tls, &s.cert_id,
		&s.is_valid, &s.validation_error, &s.is_ubuntu_valid, &s.is_mozilla_valid,
		&s.is_windows_valid, &s.is_apple_valid, &s.conn_info)

	if err != nil {
		return s, err
	}

	return s, nil

}

func (db *DB) UpdateCompletionPercentage(id string, p int) error {
	db.Exec("UPDATE")
}
