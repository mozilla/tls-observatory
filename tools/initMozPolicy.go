package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strconv"

	"github.com/mozilla/tls-observatory/certificate"
	"github.com/mozilla/tls-observatory/certificate/constraints"
	"github.com/mozilla/tls-observatory/database"
)

const listQuery = `SELECT id, raw_cert
					FROM certificates
					WHERE id > $1
					ORDER BY id ASC LIMIT $2`

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
	limit := 100
	if len(os.Args) > 1 {
		offset, err = strconv.Atoi(os.Args[1])
		if err != nil {
			log.Fatal(err)
		}
	}

	for {
		fmt.Printf("\nProcessing offset %d to %d: ", offset, offset+limit)
		rows, err := db.Query(listQuery, offset, limit)
		if rows != nil {
			defer rows.Close()
		}
		if err != nil {
			panic(fmt.Errorf("Error while retrieving certs: '%v'", err))
		}
		i := 0
		updates := make(map[int64]string)
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
			mozPolicyJSON, err := json.Marshal(certificate.MozillaPolicy{certconstraints.IsTechnicallyConstrainedMozPolicyV2_5(c)})
			if err != nil {
				fmt.Println("error while marshalling Mozilla policy", id, ":", err)
				continue
			}
			updates[id] = string(mozPolicyJSON)
		}
		if i == 0 {
			fmt.Println("done!")
			break
		}
		// batch update
		sql := "UPDATE certificates SET mozillaPolicyV2_5 = newvalues.mozPolicy FROM ( VALUES "
		first := true
		for id, mozPolicy := range updates {
			if !first {
				sql += ","
			}
			sql += fmt.Sprintf("(%d, '%s'::jsonb)", id, mozPolicy)
			first = false
		}
		sql += ") AS newvalues (id, mozPolicy) WHERE certificates.id = newvalues.id"
		_, err = db.Exec(sql)
		if err != nil {
			fmt.Printf("error while updating certificates in database: %v\nSQL statement was:\n%s", err, sql)
		}
		offset += limit
		ioutil.WriteFile("/tmp/initMozPolicy_offset", []byte(fmt.Sprintf("%d", offset)), 0700)
	}
}
