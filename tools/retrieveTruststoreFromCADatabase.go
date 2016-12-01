package main

import (
	"encoding/csv"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
)

func main() {
	var (
		truststore, csvURL string
		csvPEMPos          int
	)
	if len(os.Args) != 2 {
		log.Fatalf("usage: %s <mozilla|microsoft>", os.Args[0])
	}
	truststore = os.Args[1]
	switch truststore {
	case "mozilla":
		csvURL = "https://mozillacaprogram.secure.force.com/CA/IncludedCACertificateReportPEMCSV"
		csvPEMPos = 28
	case "microsoft":
		csvURL = "https://mozillacaprogram.secure.force.com/CA/apex/IncludedCACertificateReportForMSFTCSVPEM"
		csvPEMPos = 6
	}
	resp, err := http.Get(csvURL)
	if err != nil {
		log.Fatal(err)
	}
	r := csv.NewReader(resp.Body)
	defer resp.Body.Close()
	records, err := r.ReadAll()
	if err != nil {
		log.Fatal(err)
	}
	for _, record := range records {
		if len(record) < csvPEMPos+1 {
			continue
		}
		fmt.Println(strings.Trim(record[csvPEMPos], `'`))
	}
}
