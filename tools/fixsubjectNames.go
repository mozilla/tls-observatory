package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"

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
	// batch side: do 100 certs at a time
	limit := 100
	batch := 0
	for {
		fmt.Printf("\nProcessing batch %d to %d: ", batch*limit, batch*limit+limit)
		rows, err := db.Query(`SELECT id, raw_cert
					FROM certificates
					WHERE issuer IS NULL AND subject IS NULL AND domains IS NULL
					ORDER BY id ASC LIMIT $1`, limit)
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
			issuer := certificate.Issuer{Country: c.Issuer.Country, CommonName: c.Issuer.CommonName, OrgUnit: c.Issuer.OrganizationalUnit, Organisation: c.Issuer.Organization}

			issuerjs, err := json.Marshal(issuer)
			if err != nil {
				fmt.Println("error while marshalling issuer of cert", id, " : ", err)
				continue
			}

			subject := certificate.Subject{Country: c.Subject.Country, CommonName: c.Subject.CommonName, OrgUnit: c.Subject.OrganizationalUnit, Organisation: c.Subject.Organization}
			subjectjs, err := json.Marshal(subject)
			if err != nil {
				fmt.Println("error while marshalling subject of cert", id, " : ", err)
				continue
			}

			domainstr := ""

			if !c.IsCA {
				domainfound := false
				for _, d := range c.DNSNames {
					if d == c.Subject.CommonName {
						domainfound = true
					}
				}

				var domains []string

				if !domainfound {
					domains = append(c.DNSNames, c.Subject.CommonName)
				} else {
					domains = c.DNSNames
				}

				domainstr = strings.Join(domains, ",")
				fmt.Printf("%d,", id)
			}

			_, err = db.Exec(`UPDATE certificates SET issuer=$1, subject=$2, domains=$3 WHERE id=$4`,
				issuerjs, subjectjs, domainstr, id)
			if err != nil {
				fmt.Println("error while updating cert", id, "in database:", err)
			}
		}
		if i == 0 {
			fmt.Println("done!")
			break
		}
		//offset += limit
		batch++
	}
}
