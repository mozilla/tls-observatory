package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

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
	batch := 0
	for {
		fmt.Printf("\nProcessing batch %d to %d: ", batch, batch+200)
		rows, err := db.Query(`SELECT id, raw_cert
					FROM certificates
					WHERE serial_number IS NULL
					ORDER BY id ASC
					LIMIT 200`)
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
			serial := strings.ToUpper(hex.EncodeToString(c.SerialNumber.Bytes()))
			_, err = db.Exec(`UPDATE certificates
						SET serial_number=$1
						WHERE id=$2`,
				serial, id)
			if err != nil {
				fmt.Println("error while updating cert", id, "in database:", err)
			}
			fmt.Printf(".")
		}
		if i == 0 {
			fmt.Println("done!")
			break
		}
		batch += 200
	}
}
