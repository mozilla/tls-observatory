package main

import (
	"encoding/csv"
	"fmt"
	"log"
	"net/http"
	"strings"
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
	for _, record := range records {
		if len(record) < 27 {
			continue
		}
		fmt.Println(strings.Trim(record[26], `'`))
	}
}
