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
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/google/certificate-transparency/go"
	"github.com/google/certificate-transparency/go/client"
	"github.com/google/certificate-transparency/go/jsonclient"
	"github.com/google/certificate-transparency/go/x509"
	"github.com/mozilla/tls-observatory/certificate"
)

func main() {
	var (
		err    error
		offset int
	)
	httpCli := &http.Client{
		Transport: &http.Transport{
			DisableCompression: true,
			DisableKeepAlives:  false,
		},
		Timeout: 10 * time.Second,
	}
	// create a certificate transparency client
	ctLog, _ := client.New("http://ct.googleapis.com/aviator", httpCli, jsonclient.Options{})

	if len(os.Args) > 1 {
		offset, err = strconv.Atoi(os.Args[1])
		if err != nil {
			log.Fatal(err)
		}
	}
	for {
		log.Printf("retrieving CT logs %d to %d", offset, offset+100)
		rawEnts, err := ctLog.GetEntries(nil, int64(offset), int64(offset+100))
		if err != nil {
			log.Fatal(err)
		}

		// loop over CT records
		for i, ent := range rawEnts {
			log.Printf("CT index=%d", offset+i)
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
				log.Fatal(err)
			}
			r.Header.Set("Content-Type", w.FormDataContentType())
			resp, err := httpCli.Do(r)
			if err != nil {
				log.Printf("%v\n\n", err)
				continue
			}
			defer resp.Body.Close()
			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				log.Fatal(err)
			}
			if resp.StatusCode != http.StatusCreated {
				log.Fatalf("Expected HTTP 201 Created, got %q\n%s", resp.Status, body)
			}

			// parse the returned cert
			var tlsobs_cert certificate.Certificate
			err = json.Unmarshal(body, &tlsobs_cert)
			if err != nil {
				log.Fatal(err)
			}
			log.Printf("https://tls-observatory.services.mozilla.com/api/v1/certificate?id=%d\n\n", tlsobs_cert.ID)
		}
		offset += 100
	}
}
