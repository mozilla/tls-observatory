// this short program iterate over the certificates index
// to extract unique domains and IPs from recorded certificates
// and write them into two files in /tmp/

// Julien Vehent - Feb. 2015
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	// 3rd party dependencies
	elastigo "github.com/mattbaird/elastigo/lib"
)

type StoredCertificate struct {
	Domains []string `json:"domains,omitempty"`
	IPs     []string `json:"ips,omitempty"`
}

func main() {
	var (
		es       *elastigo.Conn
		from, to time.Time
	)
	dctr := 0
	domains := make(map[string]int)
	ictr := 0
	ips := make(map[string]int)
	es = elastigo.NewConn()
	es.Domain = os.Args[1]
	// start the search at 15 days ago, iterate over all certs by chunks of 5 minutes,
	// and build a list of unique domains
	to = time.Now().Add(-15 * 24 * time.Hour)
	for {
		// advance the window by 5 minutes
		from = to
		to = from.Add(5 * time.Minute)
		if from.After(time.Now()) {
			break
		}
		// ES query date is in format 2015-02-12T07:45:22
		filter := fmt.Sprintf(`{
			"from" : 0, "size" : 100000,
			"query": {
				"range": {
					"lastSeenTimestamp": {
						"from": "%s",
						"to": "%s"
					}
				}
			}
		}`, from.Format("2006-01-02T15:04:05"), to.Format("2006-01-02T15:04:05"))
		res, err := es.Search("certificates", "certificateInfo", nil, filter)
		if err != nil {
			panic(err)
		}
		fmt.Println(len(res.Hits.Hits), "records found for time window [", from.String(), ",", to.String(), "]")
		for _, storedCert := range res.Hits.Hits {
			fmt.Println("processing cert id", storedCert.Id)
			cert := new(StoredCertificate)
			err = json.Unmarshal(*storedCert.Source, cert)
			if err != nil {
				panic(err)
			}
			for _, d := range cert.Domains {
				if _, ok := domains[d]; !ok {
					dctr++
					domains[d] = dctr
					fmt.Println("Added domain", d, "in position", dctr)
				}
				for _, ip := range cert.IPs {
					if _, ok := ips[ip]; !ok {
						ictr++
						ips[ip] = ictr
						fmt.Println("Added IP", ip, "in position", ictr)
					}
				}
			}
		}
	}
	// write to file
	outfile := fmt.Sprintf("/tmp/domains_%d", time.Now().Unix())
	fd, err := os.Create(outfile)
	if err != nil {
		panic(err)
	}
	for domain, ctr := range domains {
		_, err := io.WriteString(fd, fmt.Sprintf("%d,%s\n", ctr, domain))
		if err != nil {
			panic(err)
		}
	}
	fd.Close()

	outfile = fmt.Sprintf("/tmp/ips_%d", time.Now().Unix())
	fd, err = os.Create(outfile)
	if err != nil {
		panic(err)
	}
	for ip, ctr := range ips {
		_, err := io.WriteString(fd, fmt.Sprintf("%d,%s\n", ctr, ip))
		if err != nil {
			panic(err)
		}
	}
	fd.Close()
}
