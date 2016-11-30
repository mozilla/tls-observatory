package main

import (
	"encoding/csv"
	"fmt"
	"log"
	"net/http"
	"strings"
)

func main() {
	resp, err := http.Get("https://mozillacaprogram.secure.force.com/CA/IncludedCACertificateReportPEMCSV")
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
		if len(record) < 29 {
			continue
		}
		fmt.Println(strings.Trim(record[28], `'`))
	}
}
