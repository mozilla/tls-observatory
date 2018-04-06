package main

import (
	"fmt"
	"net/http"
	"regexp"
	"time"

	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/scanner"
)

func main() {
	httpCli := &http.Client{
		Transport: &http.Transport{
			DisableCompression: true,
			DisableKeepAlives:  false,
		},
		Timeout: 10 * time.Second,
	}

	cli, err := client.New("https://ct.googleapis.com/pilot", httpCli, jsonclient.Options{})
	if err != nil {
		fmt.Printf("ERROR: getting CT log from Google polit, err=%v\n", err)
	}

	opts := scanner.ScannerOptions{
		Matcher:       &scanner.MatchSubjectRegex{regexp.MustCompile(".*\\.google\\.com"), nil},
		BatchSize:     10,
		NumWorkers:    1,
		ParallelFetch: 1,
		StartIndex:    0,
	}
	scan := scanner.NewScanner(cli, opts)
	fmt.Println(scan)
}
