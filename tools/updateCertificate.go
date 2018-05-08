package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/mozilla/tls-observatory/certificate"
	"github.com/mozilla/tls-observatory/database"
	diff "github.com/yudai/gojsondiff"
	"github.com/yudai/gojsondiff/formatter"
)

func main() {
	db, err := database.RegisterConnection(
		os.Getenv("TLSOBS_POSTGRESDB"),
		os.Getenv("TLSOBS_POSTGRESUSER"),
		os.Getenv("TLSOBS_POSTGRESPASS"),
		os.Getenv("TLSOBS_POSTGRES"),
		"disable")
	defer db.Close()
	if err != nil {
		panic(err)
	}
	if len(os.Args) < 2 {
		fmt.Printf("usage: updateCertificate <cert id>...\neg: updateCertificate 41 152 28631\n")
		os.Exit(1)
	}
	for i := 1; i < len(os.Args); i++ {
		certId, err := strconv.Atoi(os.Args[i])
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Processing cert id %d\n", certId)
		cert, err := db.GetCertByID(int64(certId))
		if err != nil {
			log.Fatalf("Error while retrieving cert id %d: '%v'", certId, err)
		}
		x509Cert, err := cert.ToX509()
		if err != nil {
			log.Fatal(err)
		}

		var valInfo certificate.ValidationInfo
		reparsedCert := certificate.CertToStored(x509Cert, "", "", "", "", &valInfo)
		reparsedCert.ID = cert.ID
		reparsedCert.FirstSeenTimestamp = cert.FirstSeenTimestamp
		reparsedCert.LastSeenTimestamp = cert.LastSeenTimestamp

		certJson, err := json.MarshalIndent(cert, "", "    ")
		if err != nil {
			log.Fatal(err)
		}
		reparsedCertJson, err := json.MarshalIndent(reparsedCert, "", "    ")
		if err != nil {
			log.Fatal(err)
		}
		// Then, compare them
		differ := diff.New()
		d, err := differ.Compare(certJson, reparsedCertJson)
		if err != nil {
			log.Fatal(err)
		}

		if d.Modified() {
			var (
				diffString string
				aJson      map[string]interface{}
				answer     string
			)
			json.Unmarshal(certJson, &aJson)

			formatter := formatter.NewAsciiFormatter(aJson, formatter.AsciiFormatterConfig{
				ShowArrayIndex: true,
				Coloring:       true,
			})

			diffString, _ = formatter.Format(d)
			fmt.Print(diffString)
			fmt.Print("Differences found between the original and reparsed certificates. Would you like to update the database? y/n> ")
			fmt.Scanf("%s", &answer)
			if answer == "y" {
				fmt.Printf("updated cert %d in database\n", cert.ID)
				err = db.UpdateCertificate(&reparsedCert)
				if err != nil {
					log.Fatal(err)
				}
			} else {
				fmt.Println("database update discarded")
			}
		} else {
			fmt.Println("no difference found between the original and reparsed certificates")
		}
	}
}
