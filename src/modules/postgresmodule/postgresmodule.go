package postgresmodule

import (
	"database/sql"

	_ "github.com/lib/pq"
)

type DB struct {
	*sql.DB
}

func RegisterConnection() (*DB, error) {

	db, err := sql.Open("postgres", "")

	if err != nil {
		db = nil
	}

	return &DB{db}, err
}
