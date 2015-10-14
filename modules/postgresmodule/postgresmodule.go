package postgresmodule

import (
	"database/sql"
	"fmt"
	_ "github.com/lib/pq"
)

type DB struct {
	*sql.DB
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
