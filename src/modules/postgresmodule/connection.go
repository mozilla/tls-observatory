package postgresmodule

import (
	"connection"
)

func (db *DB) InsertConnection(conn *connection.Connection) error {

	q := ""
	res, err := db.Exec(q)

	return err
}
