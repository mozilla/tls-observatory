package postgresmodule

import (
	"database/sql"
	"fmt"
	_ "github.com/lib/pq"
)

type DB struct {
	*sql.DB
}

func RegisterConnection(dbname, user, password, host string, port int, sslmode string) (*DB, error) {

	url := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s",
		user, password, host, port, dbname, sslmode)

	db, err := sql.Open("postgres", url)

	if err != nil {
		db = nil
	}

	return &DB{db}, err
}
