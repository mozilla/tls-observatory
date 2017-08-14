package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/mozilla/tls-observatory/certificate"
)

func main() {
	var (
		err       error
		offset    int
		batchSize = 100
		maxJobs   = 100
		jobCount  = 0
	)
	// if present, parse the first argument of the cmdline as offset
	if len(os.Args) > 1 {
		offset, err = strconv.Atoi(os.Args[1])
		if err != nil {
			log.Fatal(err)
		}
	}
	// create an http client for CT log
	httpCTCli := &http.Client{
		Transport: &http.Transport{
			DisableCompression: false,
			DisableKeepAlives:  false,
			Dial: (&net.Dialer{
				Timeout: 5 * time.Second,
			}).Dial,
			TLSHandshakeTimeout: 5 * time.Second,
		},
		Timeout: 60 * time.Second,
	}
	// create a certificate transparency client
	ctLog, _ := client.New("http://ct.googleapis.com/pilot", httpCTCli, jsonclient.Options{})

	// create an http client to post to tls observatory
	httpCli := &http.Client{
		Transport: &http.Transport{
			DisableCompression: false,
			DisableKeepAlives:  false,
			Dial: (&net.Dialer{
				Timeout: 30 * time.Second,
			}).Dial,
			TLSHandshakeTimeout: 30 * time.Second,
		},
		Timeout: 60 * time.Second,
	}
	for {
		log.Printf("retrieving CT logs %d to %d", offset, offset+batchSize)
		rawEnts, err := ctLog.GetEntries(nil, int64(offset), int64(offset+batchSize))
		if err != nil {
			log.Fatal(err)
		}

		// loop over CT records
		for i, ent := range rawEnts {
			for {
				if jobCount >= maxJobs {
					time.Sleep(time.Second)
				} else {
					break
				}
			}
			go func(pos int, ent ct.LogEntry) {
				jobCount++
				defer func() {
					jobCount--
				}()

				log.Printf("CT index=%d", offset+pos)
				var cert *x509.Certificate
				switch ent.Leaf.TimestampedEntry.EntryType {
				case ct.X509LogEntryType:
					cert, err = x509.ParseCertificate(ent.Leaf.TimestampedEntry.X509Entry.Data)
				case ct.PrecertLogEntryType:
					cert, err = x509.ParseTBSCertificate(ent.Leaf.TimestampedEntry.PrecertEntry.TBSCertificate)
				}
				if err != nil {
					log.Fatal(err)
				}
				log.Printf("CN=%s", cert.Subject.CommonName)
				log.Printf("Not Before=%s", cert.NotBefore)
				log.Printf("Not After=%s", cert.NotAfter)

				// Format the PEM certificate
				payload := base64.StdEncoding.EncodeToString(cert.Raw)
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

				// create a mime/multipart form with the certificate
				var b bytes.Buffer
				w := multipart.NewWriter(&b)
				fw, err := w.CreateFormFile("certificate", certificate.SHA256Hash(cert.Raw))
				if err != nil {
					log.Fatal(err)
				}
				_, err = io.Copy(fw, buf)
				if err != nil {
					log.Fatal(err)
				}
				w.Close()

				// post the form to the tls-observatory api
				r, err := http.NewRequest("POST", "https://tls-observatory.services.mozilla.com/api/v1/certificate", &b)
				if err != nil {
					log.Println(err)
					return
				}
				r.Header.Set("Content-Type", w.FormDataContentType())
				resp, err := httpCli.Do(r)
				if err != nil {
					log.Printf("%v\n\n", err)
					return
				}
				defer resp.Body.Close()
				body, err := ioutil.ReadAll(resp.Body)
				if err != nil {
					log.Println(err)
					return
				}
				if resp.StatusCode != http.StatusCreated {
					log.Printf("Expected HTTP 201 Created, got %q\n%s", resp.Status, body)
					return
				}

				// parse the returned cert
				var tlsobsCert certificate.Certificate
				err = json.Unmarshal(body, &tlsobsCert)
				if err != nil {
					log.Println(err)
					return
				}
				log.Printf("https://tls-observatory.services.mozilla.com/api/v1/certificate?id=%d\n\n", tlsobsCert.ID)

			}(i, ent)
		}
		offset += batchSize
	}
}
