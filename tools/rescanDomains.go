package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/mozilla/tls-observatory/database"
)

type scan struct {
	ID int `json:"scan_id"`
}

func main() {
	var observatory = flag.String("observatory", "https://tls-observatory.services.mozilla.com", "URL of the observatory")
	flag.Parse()
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
	var donedomains []string
	for {
		fmt.Printf("\nProcessing batch %d to %d\n", batch*limit, batch*limit+limit)
		rows, err := db.Query(`	SELECT domains
					FROM certificates INNER JOIN trust ON (trust.cert_id=certificates.id)
					WHERE is_ca='false' AND trusted_mozilla='true'
					ORDER BY certificates.id ASC LIMIT $1 OFFSET $2`, limit, batch*limit)
		if rows != nil {
			defer rows.Close()
		}
		if err != nil {
			panic(fmt.Errorf("Error while retrieving certs: '%v'", err))
		}
		i := 0
		for rows.Next() {
			i++
			var domains string
			err = rows.Scan(&domains)
			if err != nil {
				fmt.Println("error while retrieving domains:", err)
				continue
			}
			for _, domain := range strings.Split(domains, ",") {
				domain = strings.TrimSpace(domain)
				if domain == "" {
					continue
				}
				if domain[0] == '*' {
					domain = "www" + domain[1:]
				}
				if contains(donedomains, domain) {
					continue
				}
				resp, err := http.Post(*observatory+"/api/v1/scan?target="+domain, "application/json", nil)
				if err != nil {
					panic(err)
				}
				defer resp.Body.Close()
				body, err := ioutil.ReadAll(resp.Body)
				if err != nil {
					panic(err)
				}
				var scan scan
				err = json.Unmarshal(body, &scan)
				if err != nil {
					panic(err)
				}
				fmt.Printf("Started scan %d on %s - %s/api/v1/results?id=%d\n", scan.ID, domain, *observatory, scan.ID)
				donedomains = append(donedomains, domain)
				time.Sleep(500 * time.Millisecond)
			}
		}
		if i == 0 {
			fmt.Println("done!")
			break
		}
		batch++
	}
}

func contains(list []string, test string) bool {
	for _, item := range list {
		if item == test {
			return true
		}
	}
	return false
}
