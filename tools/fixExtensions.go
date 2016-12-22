package main

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/lib/pq"
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
	batch := 0
	var lastid int64
	for {
		log.Printf("Processing batch %d to %d", batch, batch+100)
		rows, err := db.Query(`SELECT id, raw_cert
					FROM certificates
					ORDER BY id ASC
					OFFSET $1 LIMIT 100`, batch)
		if rows != nil {
			defer rows.Close()
		}
		if err != nil {
			panic(fmt.Errorf("Error while retrieving certs: '%v'", err))
		}
		i := 0
		for rows.Next() {
			var raw string
			var id int64
			err = rows.Scan(&id, &raw)
			if err != nil {
				fmt.Println("error while parsing cert", id, ":", err)
				continue
			}

			if id == lastid {
				// We're processing an ID that was already processed earlier, which
				// means we're looping over the end rows. it's time to exit
				goto done
			}
			lastid = id
			i++

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
			var valInfo certificate.ValidationInfo
			cert := certificate.CertToStored(c, "", "", "", "", &valInfo)
			if err != nil {
				log.Printf("error while marshalling permitted names for cert %d: %v", id, err)
				continue
			}
			if cert.X509v3Extensions.PermittedDNSDomains == nil {
				cert.X509v3Extensions.PermittedDNSDomains = make([]string, 0)
			}
			if cert.X509v3Extensions.ExcludedDNSDomains == nil {
				cert.X509v3Extensions.ExcludedDNSDomains = make([]string, 0)
			}
			if cert.X509v3Extensions.IsTechnicallyConstrained {
				log.Printf("id=%d, permitted_dns_domains=%v, permitted_ip_addresses=%v, excluded_dns_domains=%v, excluded_ip_addresses=%v, is_technically_constrained=%t",
					id, cert.X509v3Extensions.PermittedDNSDomains, cert.X509v3Extensions.PermittedIPAddresses, cert.X509v3Extensions.ExcludedDNSDomains, cert.X509v3Extensions.ExcludedIPAddresses, cert.X509v3Extensions.IsTechnicallyConstrained)
				_, err = db.Exec(`UPDATE certificates
						SET permitted_dns_domains=$1,
						    permitted_ip_addresses=$2,
						    excluded_dns_domains=$3,
						    excluded_ip_addresses=$4,
						    is_technically_constrained=$5
						WHERE id=$6`,
					pq.Array(&cert.X509v3Extensions.PermittedDNSDomains),
					pq.Array(&cert.X509v3Extensions.PermittedIPAddresses),
					pq.Array(&cert.X509v3Extensions.ExcludedDNSDomains),
					pq.Array(&cert.X509v3Extensions.ExcludedIPAddresses),
					cert.X509v3Extensions.IsTechnicallyConstrained,
					id)
				if err != nil {
					fmt.Println("error while updating cert", id, "in database:", err)
				}
			}
			if strings.HasPrefix(cert.Serial, "-") {
				log.Printf("id=%d, serial=%s", id, cert.Serial)
				_, err = db.Exec(`UPDATE certificates
						SET serial_number=$1
						WHERE id=$2`,
					cert.Serial, id)
				if err != nil {
					fmt.Println("error while updating cert", id, "in database:", err)
				}
			}
		}
		if i == 0 {
			goto done
		}
		batch += 100
	}
done:
	fmt.Println("Processing done. Goodbye!")
}
