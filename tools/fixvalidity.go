// This is a script that fixes the validity dates of certificates
// in the database by retrieving the raw cert and updating the date
// using the original cert.
package main

import (
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/mozilla/tls-observatory/database"
)

func main() {
	db, err := database.RegisterConnection(
		os.Getenv("TLSOBS_POSTGRESDB"),
		os.Getenv("TLSOBS_POSTGRESUSER"),
		os.Getenv("TLSOBS_POSTGRESPASS"),
		os.Getenv("TLSOBS_POSTGRES"),
		"require")
	defer db.Close()
	if err != nil {
		panic(err)
	}
	// batch side: do 100 certs at a time
	limit := 100
	offset := 0
	for {
		fmt.Println("Processing batch", offset, "to", limit)
		rows, err := db.Query(`SELECT id, raw_cert FROM certificates LIMIT $1 OFFSET $2`, limit, offset)
		if rows != nil {
			defer rows.Close()
		}
		if err != nil {
			panic(fmt.Errorf("Error while retrieving certs: '%v'", err))
		}
		for rows.Next() {
			var raw string
			var id int64
			err = rows.Scan(&id, &raw)
			if err != nil {
				if err == sql.ErrNoRows {
					fmt.Println("done!")
					break
				}
				fmt.Println("error while parsing cert", id, ":", err)
				continue
			}
			certdata, err := base64.StdEncoding.DecodeString(raw)
			if err != nil {
				fmt.Println("error decoding base64 of cert", id, ":", err)
				continue
			}
			c, err := x509.ParseCertificate(certdata)
			if err != nil {
				fmt.Println("error while x509 parsing cert", id, ":", err)
				continue
			}
			fmt.Println("cert", id, "has validity", c.NotBefore, c.NotAfter, "updating in database")
			_, err = db.Exec(`UPDATE certificates SET not_valid_before=$1, not_valid_after=$2 WHERE id=$3`,
				c.NotBefore, c.NotAfter, id)
			if err != nil {
				fmt.Println("error while updating cert", id, "in database:", err)
			}
		}
		offset += limit
	}
}
