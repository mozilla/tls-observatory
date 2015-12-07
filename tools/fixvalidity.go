// This is a script that fixes the validity dates of certificates
// in the database by retrieving the raw cert and updating the date
// using the original cert.
package main

import (
	"crypto/x509"
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
		fmt.Println("Processing batch", offset, "to", offset+limit)
		rows, err := db.Query(`SELECT id, raw_cert
					FROM certificates
					WHERE not_valid_after < NOW() AND not_valid_after > NOW() - INTERVAL '4 days'
					AND not_valid_before > not_valid_after - INTERVAL '5 minutes'
					LIMIT $1 OFFSET $2`, limit, offset)
		if rows != nil {
			defer rows.Close()
		}
		if err != nil {
			panic(fmt.Errorf("Error while retrieving certs: '%v'", err))
		}
		i := 0
		for rows.Next() {
			i++
			var raw string
			var id int64
			err = rows.Scan(&id, &raw)
			if err != nil {
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
			//fmt.Println("cert", id, "has validity", c.NotBefore, c.NotAfter, "updating in database")
			_, err = db.Exec(`UPDATE certificates SET not_valid_before=$1, not_valid_after=$2 WHERE id=$3`,
				c.NotBefore, c.NotAfter, id)
			if err != nil {
				fmt.Println("error while updating cert", id, "in database:", err)
			}
		}
		if i == 0 {
			fmt.Println("done!")
			break
		}
		offset += limit
	}
}
