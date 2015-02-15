// this short program iterate over the certificates index
// to extract unique domains and IPs from recorded certificates
// and write them into two files in /tmp/

// Julien Vehent - Feb. 2015
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	elastigo "github.com/mattbaird/elastigo/lib"
	"github.com/streadway/amqp"
	"time"
)

// limit the structs to just the amount of data we need: domain names and CA status
type StoredCertificate struct {
	Subject          certSubject    `json:"subject"`
	X509v3Extensions certExtensions `json:"x509v3Extensions"`
	CA               bool           `json:"ca"`
}
type certSubject struct {
	CommonName string `json:"cn"`
}
type certExtensions struct {
	SubjectAlternativeName []string `json:"subjectAlternativeName"`
}

func main() {
	var (
		esaddr, mqaddr, window string
		es                     *elastigo.Conn
		from, to               time.Time
	)
	flag.StringVar(&esaddr, "e", "localhost:9200", "Address of the ElasticSearch database")
	flag.StringVar(&mqaddr, "m", "amqp://guest:guest@localhost:5672/", "Address of the RabbitMQ broker")
	flag.StringVar(&window, "w", "360h", "Time window to cover, in hours (360h = 15 days)")
	flag.Parse()

	es = elastigo.NewConn()
	es.Domain = esaddr

	mqconn, err := amqp.Dial(mqaddr)
	if err != nil {
		panic(err)
	}
	defer mqconn.Close()

	mqch, err := mqconn.Channel()
	if err != nil {
		panic(err)
	}
	defer mqch.Close()

	dctr := 0
	domains := make(map[string]int)

	// start the search at now - window, iterate over all certs by chunks of 5 minutes,
	// and build a list of unique domains
	dur, err := time.ParseDuration(window)
	if err != nil {
		panic(err)
	}
	to = time.Now().Add(-dur)
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
			cert := new(StoredCertificate)
			err = json.Unmarshal(*storedCert.Source, cert)
			if err != nil {
				panic(err)
			}
			// skip certificate authorities
			if cert.CA {
				continue
			}
			// build a list of domains from the certs SAN records and its subject.CN
			// then scan the ones that haven't been scanned yet
			dlist := cert.X509v3Extensions.SubjectAlternativeName
			dlist = append(dlist, cert.Subject.CommonName)
			for _, d := range dlist {
				// if a wildcard cert is found, replace it with a scan
				// of the domain itself, and another one of its www host
				if len(d) > 2 && d[0:2] == "*." {
					d = d[2:]
					dlist = append(dlist, "www."+d)
				}
				if _, ok := domains[d]; !ok {
					err = mqch.Publish(
						"",                 // exchange
						"scan_ready_queue", // routing key
						false,              // mandatory
						false,
						amqp.Publishing{
							DeliveryMode: amqp.Persistent,
							ContentType:  "text/plain",
							Body:         []byte(d),
						})
					if err != nil {
						panic(err)
					}
					dctr++
					domains[d] = dctr
					fmt.Println("send domain", d, "to scan_ready_queue")
				}
			}
		}
	}
	fmt.Println("Done.", dctr, "domains sent to scanning queue.")
}
