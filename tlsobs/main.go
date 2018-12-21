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

	"github.com/fatih/color"
	"github.com/mozilla/tls-observatory/certificate"
	"github.com/mozilla/tls-observatory/connection"
	"github.com/mozilla/tls-observatory/database"
	"github.com/mozilla/tls-observatory/worker"
	_ "github.com/mozilla/tls-observatory/worker/awsCertlint"
	_ "github.com/mozilla/tls-observatory/worker/caaWorker"
	_ "github.com/mozilla/tls-observatory/worker/crlWorker"
	_ "github.com/mozilla/tls-observatory/worker/mozillaEvaluationWorker"
	_ "github.com/mozilla/tls-observatory/worker/mozillaGradingWorker"
	_ "github.com/mozilla/tls-observatory/worker/ocspStatus"
	_ "github.com/mozilla/tls-observatory/worker/sslLabsClientSupport"
	_ "github.com/mozilla/tls-observatory/worker/symantecDistrust"
	_ "github.com/mozilla/tls-observatory/worker/top1m"
)

func usage() {
	fmt.Fprintf(os.Stderr, "%s - Scan a site using Mozilla's TLS Observatory\n"+
		"Usage: %s <options> mozilla.org\n",
		os.Args[0], os.Args[0])
}

type scan struct {
	ID int64 `json:"scan_id"`
}

var (
	observatory = flag.String("observatory", "https://tls-observatory.services.mozilla.com", "URL of the observatory")
	scanid      = flag.Int64("scanid", 0, "View results from a previous scan instead of starting a new one. eg `1234`")
	rescan      = flag.Bool("r", false, "Force a rescan instead of retrieving latest results")
	printRaw    = flag.Bool("raw", false, "Print raw JSON coming from the API")
	targetLevel = flag.String("targetLevel", "", "Evaluate target against a given configuration level. eg `old`, `intermediate`, `modern` or `all`.")
	allClients  = flag.Bool("allClients", false, "Print compatibility status all clients, instead of listing only oldest supported ones.")
	hidePaths   = flag.Bool("hidePaths", false, "Don't display the certificate paths to trusted roots.")
)

// exitCode is zero by default and non-zero if targetLevel isn't met
var exitCode int = 0

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

	target = strings.TrimPrefix(flag.Arg(0), "https://")
	// also trim http:// prefix ( in case someone has a really wrong idea of what
	// the observatory does...)
	target = strings.TrimPrefix(target, "http://")
	target = strings.TrimSuffix(target, "/") // trailing slash

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
		log.Fatalf("Scan initiation failed: %s", body)
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
		if results.Complperc == 100 && results.ScanError != "" {
			fmt.Printf("Scan failed with error: %s\n", results.ScanError)
			os.Exit(81)
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
		exitCode = 5
	} else {
		if *printRaw {
			fmt.Printf("%s\n", body)
		}
		printConnection(results.Conn_info)
		printAnalysis(results.AnalysisResults)
	}

	os.Exit(exitCode)
}

func printCert(id int64) {
	var (
		cert certificate.Certificate
		san  string
	)

	// Print certificate information
	cert = getCert(id)
	if len(cert.X509v3Extensions.SubjectAlternativeName) == 0 {
		san = "- none\n"
	} else {
		for _, name := range cert.X509v3Extensions.SubjectAlternativeName {
			san += "- " + name + "\n"
		}
	}
	fmt.Printf(`
--- Certificate ---
Subject  %s
SubjectAlternativeName
%sValidity %s to %s
SHA1     %s
SHA256   %s
SigAlg   %s
Key      %s %.0fbits %s
ID       %d
%s`,
		cert.Subject.String(), san,
		cert.Validity.NotBefore.Format(time.RFC3339), cert.Validity.NotAfter.Format(time.RFC3339),
		cert.Hashes.SHA1, cert.Hashes.SHA256, cert.SignatureAlgorithm,
		cert.Key.Alg, cert.Key.Size, cert.Key.Curve, cert.ID, cert.Anomalies)

	// Print truststore information
	green := color.New(color.FgGreen).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()
	gmark := green("✓")
	rmark := red("✘")
	moztrust, microtrust, appletrust, androtrust := rmark, rmark, rmark, rmark
	for truststore, trust := range cert.ValidationInfo {
		if !trust.IsValid {
			continue
		}
		switch truststore {
		case "Mozilla":
			moztrust = gmark
		case "Microsoft":
			microtrust = gmark
		case "Apple":
			appletrust = gmark
		case "Android":
			androtrust = gmark
		}
	}
	fmt.Printf(`
--- Trust ---
Mozilla Microsoft Apple Android
   %s        %s       %s      %s
`, moztrust, microtrust, appletrust, androtrust)

	if !*hidePaths {
		fmt.Printf("\n--- Trust paths ---\n%s\n", getPaths(cert.ID).String())
	}
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
		var (
			results []string
			err     error
		)
		if _, ok := worker.AvailablePrinters[a.Analyzer]; !ok {
			//fmt.Fprintf(os.Stderr, "analyzer %q not found\n", a.Analyzer)
			continue
		}
		runner := worker.AvailablePrinters[a.Analyzer].Runner
		switch a.Analyzer {
		case "mozillaEvaluationWorker":
			results, err = runner.(worker.HasAnalysisPrinter).AnalysisPrinter([]byte(a.Result), *targetLevel)
		case "sslLabsClientSupport":
			results, err = runner.(worker.HasAnalysisPrinter).AnalysisPrinter([]byte(a.Result), *allClients)
		default:
			results, err = runner.(worker.HasAnalysisPrinter).AnalysisPrinter([]byte(a.Result), nil)
		}
		for _, result := range results {
			fmt.Println(result)
		}
		if err != nil {
			fmt.Println(err)
			exitCode = 10
		}
	}
}

func getCert(id int64) (cert certificate.Certificate) {
	resp, err := http.Get(fmt.Sprintf("%s/api/v1/certificate?id=%d", *observatory, id))
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	if resp.StatusCode != http.StatusOK {
		log.Fatalf("Failed to access certificate. HTTP %d: %s", resp.StatusCode, body)
	}
	if *printRaw {
		fmt.Printf("%s\n", body)
	}
	err = json.Unmarshal(body, &cert)
	if err != nil {
		log.Fatal(err)
	}
	return
}

func getPaths(id int64) (paths certificate.Paths) {
	resp, err := http.Get(fmt.Sprintf("%s/api/v1/paths?id=%d", *observatory, id))
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	if resp.StatusCode != http.StatusOK {
		log.Fatalf("Failed to access certificate paths. HTTP %d: %s", resp.StatusCode, body)
	}
	if *printRaw {
		fmt.Printf("%s\n", body)
	}
	err = json.Unmarshal(body, &paths)
	if err != nil {
		log.Fatal(err)
	}
	return
}
