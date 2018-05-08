/* Script that pulls certificates from the CT log
   and inserts them into the observatory database

   usage: TLSOBS_DBUSER=tlsobsapi TLSOBS_DBPASS=mysecretpassphrase TLSOBS_DBHOST=127.0.0.1:5432 go run pullCTLogsIntoDB.go
*/
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"crypto/x509"

	"github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	ctx509 "github.com/google/certificate-transparency-go/x509"
	"github.com/mozilla/tls-observatory/certificate"
	pg "github.com/mozilla/tls-observatory/database"
)

const CTBATCHSIZE = 100

func main() {
	var (
		err    error
		offset int
	)
	db, err := pg.RegisterConnection(
		"observatory",
		os.Getenv("TLSOBS_DBUSER"),
		os.Getenv("TLSOBS_DBPASS"),
		os.Getenv("TLSOBS_DBHOST"),
		"require")
	defer db.Close()
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	var one uint
	err = db.QueryRow("SELECT 1").Scan(&one)
	if err != nil {
		log.Fatal("Database connection failed:", err)
	}
	if one != 1 {
		log.Fatal("Apparently the database doesn't know the meaning of one anymore. Crashing.")
	}

	httpCli := &http.Client{
		Transport: &http.Transport{
			DisableCompression: true,
			DisableKeepAlives:  false,
		},
		Timeout: 10 * time.Second,
	}
	// create a certificate transparency client
	ctLog, err := client.New(os.Getenv("CTLOG"), httpCli, jsonclient.Options{})
	if err != nil {
		log.Fatalf("Failed to connect to CT log: %v", err)
	}
	if len(os.Args) > 1 {
		offset, err = strconv.Atoi(os.Args[1])
		if err != nil {
			log.Fatal(err)
		}
	}
	for {
		log.Printf("retrieving CT logs %d to %d", offset, offset+CTBATCHSIZE)
		rawEnts, err := ctLog.GetEntries(nil, int64(offset), int64(offset+CTBATCHSIZE))
		if err != nil {
			log.Println("Failed to retrieve entries from CT log: ", err)
			time.Sleep(10 * time.Second)
			continue
		}
		// loop over CT records
		for i, ent := range rawEnts {
			log.Printf("CT index=%d", offset+i)
			var ctcertX509 *ctx509.Certificate
			switch ent.Leaf.TimestampedEntry.EntryType {
			case ct.X509LogEntryType:
				ctcertX509, err = ctx509.ParseCertificate(ent.Leaf.TimestampedEntry.X509Entry.Data)
			case ct.PrecertLogEntryType:
				ctcertX509, err = ctx509.ParseTBSCertificate(ent.Leaf.TimestampedEntry.PrecertEntry.TBSCertificate)
			}
			if err != nil {
				log.Printf("Failed to parse CT certificate: %v", err)
				continue
			}
			log.Printf("CN=%s; Issuer=%s", ctcertX509.Subject.CommonName, ctcertX509.Issuer.CommonName)
			log.Printf("Not Before=%s; Not After=%s", ctcertX509.NotBefore, ctcertX509.NotAfter)
			certHash := certificate.SHA256Hash(ctcertX509.Raw)
			id, err := db.GetCertIDBySHA256Fingerprint(certHash)
			if err != nil {
				log.Printf("Failed to lookup certificate hash %s in database: %v", certHash, err)
				continue
			}
			if id > 0 {
				// if the cert already exists in DB, return early
				log.Printf("Certificate is already in database: id=%d", id)
				continue
			}

			// Format the PEM certificate, this is silly but we need to because the CT x509 is
			// different from the crypto/x509 type
			payload := base64.StdEncoding.EncodeToString(ctcertX509.Raw)
			buf := new(bytes.Buffer)
			fmt.Fprintf(buf, "-----BEGIN CERTIFICATE-----\n")
			for len(payload) > 0 {
				chunkLen := len(payload)
				if chunkLen > 64 {
					chunkLen = 64
				}
				fmt.Fprintf(buf, "%s\n", payload[0:chunkLen])
				payload = payload[chunkLen:]
			}
			fmt.Fprintf(buf, "-----END CERTIFICATE-----")
			block, _ := pem.Decode(buf.Bytes())
			if block == nil {
				log.Printf("Failed to parse certificate PEM")
				continue
			}
			certX509, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				log.Printf("Could not parse X.509 certificate: %v", err)
				continue
			}

			var valInfo certificate.ValidationInfo
			cert := certificate.CertToStored(certX509, certHash, "", "", "", &valInfo)
			id, err = db.InsertCertificate(&cert)
			if err != nil {
				log.Print("Failed to store certificate in database: %v", err)
				continue
			}
			cert.ID = id
			// If the cert is self-signed (aka. Root CA), we're done here
			if cert.IsSelfSigned() {
				log.Print("Certificate is self-signed")
				continue
			}

			// to insert the trust, first build the certificate paths, then insert one trust
			// entry for each known parent of the cert
			paths, err := db.GetCertPaths(&cert)
			if err != nil {
				log.Printf("Failed to retrieve chains from database: %v", err)
				continue
			}
			for _, parent := range paths.Parents {
				cert.ValidationInfo = parent.GetValidityMap()
				_, err := db.InsertTrustToDB(cert, cert.ID, parent.Cert.ID)
				if err != nil {
					log.Printf("Failed to store trust in database: %v", err)
					continue
				}
			}
			log.Printf("URL = https://tls-observatory.services.mozilla.com/static/certsplainer.html?id=%d", id)
		}
		offset += CTBATCHSIZE
	}
}
