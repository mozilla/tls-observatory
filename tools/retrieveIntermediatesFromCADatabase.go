package main

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"mime/multipart"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/mozilla/tls-observatory/certificate"
)

func main() {
	resp, err := http.Get("https://ccadb-public.secure.force.com/mozilla/PublicAllIntermediateCertsWithPEMCSV")
	if err != nil {
		log.Fatal(err)
	}
	r := csv.NewReader(resp.Body)
	defer resp.Body.Close()
	records, err := r.ReadAll()
	if err != nil {
		log.Println(records)
		log.Fatal(err)
	}
	httpCli := &http.Client{
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
	for i, record := range records {
		if i == 0 {
			continue // skip the header
		}
		if len(record) < 24 {
			continue
		}
		// create a mime/multipart form with the certificate
		fmt.Println(strings.Trim(record[23], `'`))
		pemBuf := bytes.NewBufferString(strings.Trim(record[23], `'`))
		var b bytes.Buffer
		w := multipart.NewWriter(&b)
		fw, err := w.CreateFormFile("certificate", record[8])
		if err != nil {
			log.Fatal(err)
		}
		_, err = io.Copy(fw, pemBuf)
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

	}
}
