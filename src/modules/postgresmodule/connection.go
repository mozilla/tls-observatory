package postgresmodule

import (
	"connection"
)

func (db *DB) InsertConnection(conn *connection.Stored) error {

	q := ""
	_, err := db.Exec(q)

	return err
}
