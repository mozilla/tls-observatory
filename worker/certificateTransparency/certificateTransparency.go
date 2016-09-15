package main

import (
	"regexp"

	"github.com/google/certificate-transparency/go/client"
	"github.com/google/certificate-transparency/go/scanner"
)

func main() {
	cli := client.New("https://ct.googleapis.com/pilot")
	opts := ScannerOptions{
		Matcher:       &scanner.MatchSubjectRegex{regexp.MustCompile(".*\\.google\\.com"), nil},
		BatchSize:     10,
		NumWorkers:    1,
		ParallelFetch: 1,
		StartIndex:    0,
	}
	scan := scanner.NewScanner(cli, nil)

}
