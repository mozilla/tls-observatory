package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"

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
	for {
		fmt.Printf("\nProcessing batch %d to %d: ", batch, batch+100)
		rows, err := db.Query(`SELECT id, raw_cert
					FROM certificates
					ORDER BY id ASC
					LIMIT 100`)
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
			var valInfo certificate.ValidationInfo
			cert := certificate.CertToStored(c, "", "", "", "", &valInfo)
			policies, err := json.Marshal(cert.X509v3Extensions.PolicyIdentifiers)
			if err != nil {
				log.Printf("error while marshalling policies for cert %d: %v", id, err)
				continue
			}
			if err != nil {
				log.Printf("error while marshalling permitted names for cert %d: %v", id, err)
				continue
			}
			ipNetSliceToStringSlice := func(in []net.IPNet) []string {
				out := make([]string, 0)
				for _, ipnet := range in {
					out = append(out, ipnet.String())
				}
				return out
			}
			permittedIPAddresses := ipNetSliceToStringSlice(cert.X509v3Extensions.PermittedIPAddresses)
			excludedIPAddresses := ipNetSliceToStringSlice(cert.X509v3Extensions.ExcludedIPAddresses)
			if cert.X509v3Extensions.PermittedDNSDomains == nil {
				cert.X509v3Extensions.PermittedDNSDomains = make([]string, 0)
			}
			if cert.X509v3Extensions.ExcludedDNSDomains == nil {
				cert.X509v3Extensions.ExcludedDNSDomains = make([]string, 0)
			}
			log.Printf("id=%d, subject=%s, policies=%s, is_technically_constrained=%t", id, cert.Subject.String(),
				policies, cert.X509v3Extensions.IsTechnicallyConstrained)
			_, err = db.Exec(`UPDATE certificates
						SET x509_certificatepolicies=$1,
						    permitted_dns_domains=$2,
						    permitted_ip_addresses=$3,
						    excluded_dns_domains=$4,
						    excluded_ip_addresses=$5,
						    is_technically_constrained=$6
						WHERE id=$7`,
				policies,
				pq.Array(&cert.X509v3Extensions.PermittedDNSDomains),
				pq.Array(&permittedIPAddresses),
				pq.Array(&cert.X509v3Extensions.ExcludedDNSDomains),
				pq.Array(&excludedIPAddresses),
				cert.X509v3Extensions.IsTechnicallyConstrained,
				id)
			if err != nil {
				fmt.Println("error while updating cert", id, "in database:", err)
			}
			fmt.Printf(".")
		}
		if i == 0 {
			fmt.Println("done!")
			break
		}
		//offset += limit
		batch += 100
	}
}
