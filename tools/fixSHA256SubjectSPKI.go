package main

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strconv"

	"github.com/mozilla/tls-observatory/certificate"
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
	offset := 0
	limit := 1000
	if len(os.Args) > 1 {
		offset, err = strconv.Atoi(os.Args[1])
		if err != nil {
			log.Fatal(err)
		}
	}

	for {
		fmt.Printf("\nProcessing offset %d to %d: ", offset, offset+limit)
		rows, err := db.Query(`SELECT id, raw_cert
					FROM certificates
					WHERE id > $1
					AND is_ca = false
					ORDER BY id ASC LIMIT $2`, offset, limit)
		if rows != nil {
			defer rows.Close()
		}
		if err != nil {
			panic(fmt.Errorf("Error while retrieving certs: '%v'", err))
		}
		i := 0
		updates := make(map[int64]string)
		newOffset := offset
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
			updates[id] = certificate.SubjectSPKISHA256(c)
			// move the offset forward to the highest ID
			if int(id) > newOffset {
				newOffset = int(id)
			}
		}
		if i == 0 {
			fmt.Println("done!")
			break
		}
		// batch update
		sql := "UPDATE certificates SET sha256_subject_spki = newvalues.spki FROM ( VALUES "
		first := true
		for id, spki := range updates {
			if !first {
				sql += ","
			}
			sql += fmt.Sprintf("(%d, '%s')", id, spki)
			first = false
		}
		sql += ") AS newvalues (id, spki) WHERE certificates.id = newvalues.id"
		_, err = db.Exec(sql)
		if err != nil {
			fmt.Printf("error while updating certificates in database: %v\nSQL statement was:\n%s", err, sql)
		}
		if newOffset == offset {
			log.Println("no certs to update found in this batch")
			offset += limit
		} else {
			offset = newOffset
		}
		ioutil.WriteFile("/tmp/fixSHA256SubjectSPKI_offset", []byte(fmt.Sprintf("%d", offset)), 0700)
	}
}
