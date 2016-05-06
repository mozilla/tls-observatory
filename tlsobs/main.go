package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/mozilla/tls-observatory/certificate"
	"github.com/mozilla/tls-observatory/connection"
	"github.com/mozilla/tls-observatory/database"
	"github.com/mozilla/tls-observatory/worker"
	_ "github.com/mozilla/tls-observatory/worker/mozillaEvaluationWorker"
)

func usage() {
	fmt.Fprintf(os.Stderr, "%s - Scan a site using Mozilla's TLS Observatory\n"+
		"Usage: %s <options> mozilla.org\n",
		os.Args[0], os.Args[0])
}

type scan struct {
	ID int `json:"scan_id"`
}

var observatory = flag.String("observatory", "https://tls-observatory.services.mozilla.com", "URL of the observatory")
var scanid = flag.Int("scanid", 0, "View results from a previous scan instead of starting a new one")
var rescan = flag.Bool("r", false, "Force a rescan instead of retrieving latest results")
var printRaw = flag.Bool("raw", false, "Print raw JSON coming from the API")

func main() {
	var (
		err     error
		scan    scan
		rescanP string
		results database.Scan
		resp    *http.Response
		body    []byte
		target  string
	)
	flag.Usage = func() {
		usage()
		flag.PrintDefaults()
	}
	flag.Parse()
	if *scanid > 0 {
		goto getresults
	}
	if len(flag.Args()) != 1 {
		fmt.Println("error: must take only 1 non-flag argument as the target")
		usage()
		os.Exit(1)
	}
	target = flag.Arg(0)
	if *rescan {
		rescanP = "&rescan=true"
	}
	resp, err = http.Post(*observatory+"/api/v1/scan?target="+target+rescanP, "application/json", nil)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	if resp.StatusCode != http.StatusOK {
		log.Fatalf("Scan failed. HTTP %d: %s", resp.StatusCode, body)
	}
	err = json.Unmarshal(body, &scan)
	if err != nil {
		panic(err)
	}
	*scanid = scan.ID
	fmt.Printf("Scanning %s (id %d)\n", flag.Arg(0), *scanid)
getresults:
	has_cert := false
	for {
		resp, err = http.Get(fmt.Sprintf("%s/api/v1/results?id=%d", *observatory, *scanid))
		if err != nil {
			panic(err)
		}
		defer resp.Body.Close()
		body, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			panic(err)
		}
		if resp.StatusCode != http.StatusOK {
			fmt.Printf("[error] received status code %d, expected %d.\n%s",
				resp.StatusCode, http.StatusOK, body)
			os.Exit(123)
		}
		err = json.Unmarshal(body, &results)
		if err != nil {
			panic(err)
		}
		if results.Complperc == 100 && !has_cert {
			// completion is already 100% and we have not yet retrieved the cert,
			// that means the results were cached. Display a message saying so.
			fmt.Printf("Retrieving cached results from %s ago. To run a new scan, use '-r'.\n",
				time.Now().Sub(results.Timestamp).String())
		}
		if results.Cert_id > 0 && !has_cert {
			printCert(results.Cert_id)
			has_cert = true
		}
		if results.Complperc == 100 {
			break
		}
		if has_cert {
			fmt.Printf(".")
		}
		time.Sleep(1 * time.Second)
	}
	fmt.Printf("\n")
	if !results.Has_tls {
		fmt.Printf("%s does not support SSL/TLS\n", target)
	} else {
		if *printRaw {
			fmt.Printf("%s\n", body)
		}
		printConnection(results.Conn_info)
		printAnalysis(results.AnalysisResults)
	}
}

func printCert(id int64) {
	var (
		cert certificate.Certificate
		san  string
	)
	fmt.Println("\n--- Certificate ---")
	resp, err := http.Get(fmt.Sprintf("%s/api/v1/certificate?id=%d", *observatory, id))
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	if *printRaw {
		fmt.Printf("%s\n", body)
	}
	err = json.Unmarshal(body, &cert)
	if err != nil {
		panic(err)
	}
	if len(cert.X509v3Extensions.SubjectAlternativeName) == 0 {
		san = "- none"
	} else {
		for _, name := range cert.X509v3Extensions.SubjectAlternativeName {
			san += "- " + name + "\n"
		}
	}
	fmt.Printf(`Subject  %s	
SubjectAlternativeName
%sIssuer   %s
Validity %s to %s
CA       %t
SHA1     %s
SHA256   %s
SigAlg   %s
Key      %s %.0fbits %s
%s`, cert.Subject.String(), san, cert.Issuer.String(),
		cert.Validity.NotBefore.Format(time.RFC3339), cert.Validity.NotAfter.Format(time.RFC3339),
		cert.CA, cert.Hashes.SHA1, cert.Hashes.SHA256, cert.SignatureAlgorithm,
		cert.Key.Alg, cert.Key.Size, cert.Key.Curve, cert.Anomalies)
}

func printConnection(c connection.Stored) {
	fmt.Println("\n--- Ciphers Evaluation ---")
	w := new(tabwriter.Writer)
	w.Init(os.Stdout, 5, 0, 1, ' ', 0)
	fmt.Fprintf(w, "prio\tcipher\tprotocols\tpfs\tcurves\n")
	for i, entry := range c.CipherSuite {
		var (
			protos string
		)
		for _, proto := range entry.Protocols {
			if protos != "" {
				protos += ","
			}
			protos += proto
		}
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\n", i+1,
			entry.Cipher, protos, entry.PFS, strings.Join(entry.Curves, ","))
	}
	w.Flush()
	fmt.Printf(`OCSP Stapling        %t
Server Side Ordering %t
Curves Fallback      %t
`, c.CipherSuite[0].OCSPStapling, c.ServerSide, c.CurvesFallback)
}

func printAnalysis(ars []database.Analysis) {
	if len(ars) == 0 {
		return
	}
	fmt.Println("\n--- Analyzers ---")
	for _, a := range ars {
		if _, ok := worker.AvailableWorkers[a.Analyzer]; !ok {
			fmt.Fprintf(os.Stderr, "analyzer %q not found\n", a.Analyzer)
			continue
		}
		runner := worker.AvailableWorkers[a.Analyzer].Runner
		results, err := runner.(worker.HasAnalysisPrinter).AnalysisPrinter([]byte(a.Result))
		if err != nil {
			fmt.Println(err)
			continue
		}
		for _, result := range results {
			fmt.Println(result)
		}
	}
}
