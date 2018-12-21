package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path"
	"sort"
	"strconv"
	"time"

	"bytes"
	"crypto/sha256"

	"github.com/mozilla/tls-observatory/certificate"
	pg "github.com/mozilla/tls-observatory/database"
)

var scanRefreshRate float64

type scanResponse struct {
	ID int64 `json:"scan_id"`
}

func IndexHandler(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/static/index.html", http.StatusFound)
}

// ScanHandler handles the /scans endpoint of the api
// It initiates new scans and returns created scans ids to be used against other endpoints.
func ScanHandler(w http.ResponseWriter, r *http.Request) {
	var (
		status int
		err    error
	)
	defer func() {
		if nil != err {
			http.Error(w, err.Error(), status)
		}
	}()
	status = http.StatusInternalServerError

	val := r.Context().Value(ctxDBKey)
	if val == nil {
		httpError(w, r, http.StatusInternalServerError,
			fmt.Sprintf("Could not find database handler in request context"))
		return
	}
	db := val.(*pg.DB)

	params := r.FormValue("params")
	if len(params) == 0 {
		params = "{}"
	}
	domain := r.FormValue("target")
	if !validateDomain(domain) {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	rescan := r.FormValue("rescan") == "true"
	previd, prevtime, err := db.GetLastScanTimeForTarget(domain)
	if err != nil {
		httpError(w, r, http.StatusInternalServerError,
			fmt.Sprintf("Could not get last scan %q for target: %v", domain, err))
		return
	}

	now := time.Now().UTC()

	if previd != -1 { // check if previous scan exists
		if now.Sub(prevtime).Hours() <= scanRefreshRate {
			if !rescan {
				// no rescan requested so return previous scan in any case
				// this includes the rate limiting with no rescan case
				sr := scanResponse{
					ID: previd,
				}
				respBody, _ := json.Marshal(sr)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				w.Write(respBody)
				return
			}

			// forced rescan has been requested
			if now.Sub(prevtime).Minutes() <= 3 { // rate limit scan requests for same target
				if rescan {
					w.WriteHeader(429) // 429 http status code is not exported ( https://codereview.appspot.com/7678043/ )
					w.Header().Set("Content-Type", "text/html")
					fmt.Fprint(w, fmt.Sprintf("Last scan for target %s initiated %s ago.\nPlease try again in %s.\n", domain, now.Sub(prevtime), 3*time.Minute-now.Sub(prevtime)))
					return
				}
			}
		}
	}

	//initiating a new scan
	scan, err := db.NewScan(domain, -1, []byte(params)) //no replay
	if err != nil {
		httpError(w, r, http.StatusInternalServerError,
			fmt.Sprintf("Could not create new scan: %v", err))
		return
	}
	sr := scanResponse{
		ID: scan.ID,
	}
	respBody, err := json.Marshal(sr)
	if err != nil {
		httpError(w, r, http.StatusInternalServerError,
			fmt.Sprintf("Failed to convert scan ID %d to JSON: %v", scan.ID, err))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(respBody)
}

// ResultHandler handles the results endpoint of the api.
// It has a scan id as input and returns its results ( if available )
func ResultHandler(w http.ResponseWriter, r *http.Request) {
	var (
		status int
		err    error
	)
	defer func() {
		if nil != err {
			http.Error(w, err.Error(), status)
		}
	}()
	val := r.Context().Value(ctxDBKey)
	if val == nil {
		httpError(w, r, http.StatusInternalServerError,
			fmt.Sprintf("Could not find database handler in request context"))
		return
	}

	db := val.(*pg.DB)

	idStr := r.FormValue("id")

	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		httpError(w, r, http.StatusBadRequest,
			fmt.Sprintf("Could not parse provided scan id %q: %v", idStr, err))
		return
	}

	scan, err := db.GetScanByID(id)
	if err != nil {
		httpError(w, r, http.StatusInternalServerError,
			fmt.Sprintf("Failed to retrieve scan id %d from database: %v", id, err))
		return
	}

	if scan.ID == -1 {
		httpError(w, r, http.StatusBadRequest,
			fmt.Sprintf("Failed to find scan id %d in database", id))
		return
	}

	// display the analysis results in alphabetical order of worker name
	sort.Sort(scan.AnalysisResults)

	jsScan, err := json.Marshal(scan)
	if err != nil {
		httpError(w, r, http.StatusInternalServerError,
			fmt.Sprintf("Failed to convert scan data into JSON: %v", err))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, string(jsScan))
}

// CertificateHandler handles the /certificate endpoint of the api.
// It queries the database for the provided cert ids or sha256 and returns results in JSON.
func CertificateHandler(w http.ResponseWriter, r *http.Request) {
	var (
		err error
		id  int64
	)
	val := r.Context().Value(ctxDBKey)
	if val == nil {
		httpError(w, r, http.StatusInternalServerError,
			fmt.Sprintf("Could not find database handler in request context"))
		return
	}
	db := val.(*pg.DB)

	if r.FormValue("id") != "" {
		id, err = strconv.ParseInt(r.FormValue("id"), 10, 64)
		if err != nil {
			httpError(w, r, http.StatusBadRequest,
				fmt.Sprintf("Could not parse certificate id: %v", err))
			return
		}
	} else if r.FormValue("sha256") != "" {
		id, err = db.GetCertIDBySHA256Fingerprint(r.FormValue("sha256"))
		if err != nil {
			httpError(w, r, http.StatusInternalServerError,
				fmt.Sprintf("Could not retrieve certificate: %v", err))
			return
		}
	} else {
		httpError(w, r, http.StatusBadRequest, "Certificate ID or SHA256 are missing")
		return
	}
	jsonCertFromID(w, r, id)
	return
}

// PostCertificateHandler handles the POST /certificate endpoint of the api.
// It receives a single PEM encoded certificate, parses it, inserts it
// into the database and returns results in JSON.
func PostCertificateHandler(w http.ResponseWriter, r *http.Request) {
	val := r.Context().Value(ctxDBKey)
	if val == nil {
		httpError(w, r, http.StatusInternalServerError,
			fmt.Sprintf("Could not find database handler in request context"))
		return
	}
	db := val.(*pg.DB)

	_, certHeader, err := r.FormFile("certificate")
	if err != nil {
		httpError(w, r, http.StatusBadRequest,
			fmt.Sprintf("Could not read certificate from request: %v", err))
		return
	}

	certReader, err := certHeader.Open()
	if err != nil {
		httpError(w, r, http.StatusBadRequest,
			fmt.Sprintf("Could not open certificate from form data: %v", err))
		return
	}

	certPEM, err := ioutil.ReadAll(certReader)
	if err != nil {
		httpError(w, r, http.StatusBadRequest,
			fmt.Sprintf("Could not read certificate from form data: %v", err))
		return
	}

	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		httpError(w, r, http.StatusBadRequest,
			"Failed to parse certificate PEM")
		return
	}

	certX509, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		httpError(w, r, http.StatusBadRequest,
			fmt.Sprintf("Could not parse X.509 certificate: %v", err))
		return
	}

	certHash := certificate.SHA256Hash(certX509.Raw)
	id, err := db.GetCertIDBySHA256Fingerprint(certHash)
	if err != nil {
		httpError(w, r, http.StatusInternalServerError,
			fmt.Sprintf("Failed to lookup certificate hash in database: %v", err))
		return
	}
	if id > 0 {
		// if the cert already exists in DB, return early
		log.Printf("cert id %d already exists in database, returning it", id)
		jsonCertFromID(w, r, id)
		return
	}

	var valInfo certificate.ValidationInfo
	cert := certificate.CertToStored(certX509, certHash, "", "", "", &valInfo)
	id, err = db.InsertCertificate(&cert)
	if err != nil {
		httpError(w, r, http.StatusInternalServerError,
			fmt.Sprintf("Failed to store certificate in database: %v", err))
		return
	}
	cert.ID = id
	// If the cert is self-signed (aka. Root CA), we're done here
	if cert.IsSelfSigned() {
		jsonCertFromID(w, r, cert.ID)
		return
	}

	// to insert the trust, first build the certificate paths, then insert one trust
	// entry for each known parent of the cert
	paths, err := db.GetCertPaths(&cert)
	if err != nil {
		httpError(w, r, http.StatusInternalServerError,
			fmt.Sprintf("Failed to retrieve chains from database: %v", err))
		return
	}
	for _, parent := range paths.Parents {
		cert.ValidationInfo = parent.GetValidityMap()
		_, err := db.InsertTrustToDB(cert, cert.ID, parent.Cert.ID)
		if err != nil {
			httpError(w, r, http.StatusInternalServerError,
				fmt.Sprintf("Failed to store trust in database: %v", err))
			return
		}
	}

	jsonCertFromID(w, r, cert.ID)
	return
}

// PathsHandler handles the /paths endpoint of the api.
// It queries the database for the provided cert ids or sha256 and returns
// its chain of trust in JSON.
func PathsHandler(w http.ResponseWriter, r *http.Request) {
	var (
		err error
		id  int64
	)
	val := r.Context().Value(ctxDBKey)
	if val == nil {
		httpError(w, r, http.StatusInternalServerError,
			fmt.Sprintf("Could not find database handler in request context"))
		return
	}
	db := val.(*pg.DB)

	if r.FormValue("id") != "" {
		id, err = strconv.ParseInt(r.FormValue("id"), 10, 64)
		if err != nil {
			httpError(w, r, http.StatusBadRequest,
				fmt.Sprintf("Could not parse certificate id: %v", err))
			return
		}
	} else if r.FormValue("sha256") != "" {
		id, err = db.GetCertIDBySHA256Fingerprint(r.FormValue("sha256"))
		if err != nil {
			httpError(w, r, http.StatusInternalServerError,
				fmt.Sprintf("Could not retrieve certificate: %v", err))
			return
		}
	} else {
		httpError(w, r, http.StatusBadRequest, "Certificate ID or SHA256 are missing")
		return
	}
	cert, err := db.GetCertByID(id)
	if err != nil {
		httpError(w, r, http.StatusInternalServerError,
			fmt.Sprintf("Could not retrieved stored certificate from database: %v", err))
		return
	}
	paths, err := db.GetCertPaths(cert)
	if err != nil {
		httpError(w, r, http.StatusInternalServerError,
			fmt.Sprintf("Failed to retrieve certificate paths from database: %v", err))
		return
	}
	pathsJson, err := json.Marshal(paths)
	if err != nil {
		httpError(w, r, http.StatusInternalServerError,
			fmt.Sprintf("Could not convert certificate paths to JSON: %v", err))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(pathsJson)
	return
}

// TruststoreHandler handles the /truststore endpoint of the api.
// It queries the database for all certificates trusted by a certain program.
// It takes the following parameters as HTTP query parameters:
//     store: one of {"mozilla", "android", "apple", "microsoft", "ubuntu"}
//     format: one of {"json", "pem"}
func TruststoreHandler(w http.ResponseWriter, r *http.Request) {
	val := r.Context().Value(ctxDBKey)
	if val == nil {
		httpError(w, r, http.StatusInternalServerError,
			fmt.Sprintf("Could not find database handler in request context"))
		return
	}
	db := val.(*pg.DB)
	certs, err := db.GetAllCertsInStore(r.FormValue("store"))
	if err == pg.ErrInvalidCertStore {
		httpError(w, r, http.StatusBadRequest, fmt.Sprintf("Invalid certificate trust store provided: %s", r.FormValue("store")))
		return
	} else if err != nil {
		httpError(w, r, http.StatusBadRequest, "Error querying trust store: %v", err)
		return
	}
	switch r.FormValue("format") {
	case "json":
		certsJSON, err := json.Marshal(certs)
		if err != nil {
			httpError(w, r, http.StatusInternalServerError, "Could not marshal certificates")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(certsJSON)
	case "pem":
		var buffer bytes.Buffer
		for _, cert := range certs {
			x509, err := cert.ToX509()
			if err != nil {
				httpError(w, r, http.StatusInternalServerError, "Could not convert certificate to X509")
				return
			}
			fingerprint := sha256.Sum256(x509.Raw)
			buffer.Write([]byte(fmt.Sprintf(`# Certificate "%s"
# Issuer: %s
# Serial Number: %x
# Subject: %s
# Not Valid Before: %s
# Not Valid After : %s
# Fingerprint (SHA256): %x
`,
				x509.Subject.CommonName,
				cert.Issuer.String(),
				x509.SerialNumber,
				cert.Subject.String(),
				x509.NotBefore,
				x509.NotAfter,
				fingerprint,
			)))
			err = pem.Encode(&buffer, &pem.Block{Type: "CERTIFICATE", Bytes: x509.Raw})
			if err != nil {
				httpError(w, r, http.StatusInternalServerError, "Error PEM-encoding certificate")
				return
			}
		}
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		buffer.WriteTo(w)
	default:
		httpError(w, r, http.StatusBadRequest, "Invalid output format")
	}
}

// IssuerEECount contains a certificate and the count of end-entity certs
// it has issued
type IssuerEECount struct {
	Issuer  *certificate.Certificate `json:"issuer"`
	EECount int64                    `json:"eecount"`
}

// IssuerEECountHandler handles the /issuereecount endpoint of the api.
// It queries the database for a count of end-entity certs which chain via the
// given certificate.
// It takes the following HTTP parameter:
//     sha256 - a hex encoded sha256 certificate fingerprint
func IssuerEECountHandler(w http.ResponseWriter, r *http.Request) {
	var (
		err           error
		id            int64
		issuerEECount IssuerEECount
	)
	val := r.Context().Value(ctxDBKey)
	if val == nil {
		httpError(w, r, http.StatusInternalServerError,
			fmt.Sprintf("Could not find database handler in request context"))
		return
	}
	db := val.(*pg.DB)
	if r.FormValue("id") != "" {
		id, err = strconv.ParseInt(r.FormValue("id"), 10, 64)
		if err != nil {
			httpError(w, r, http.StatusBadRequest,
				fmt.Sprintf("Could not parse certificate id: %v", err))
			return
		}
	} else if r.FormValue("sha256") != "" {
		id, err = db.GetCertIDBySHA256Fingerprint(r.FormValue("sha256"))
		if err != nil {
			httpError(w, r, http.StatusInternalServerError,
				fmt.Sprintf("Could not retrieve certificate: %v", err))
			return
		}
	} else {
		httpError(w, r, http.StatusBadRequest, "Certificate ID or SHA256 are missing")
		return
	}
	issuerEECount.EECount, err = db.GetEECountForIssuerByID(id)
	if err != nil {
		httpError(w, r, http.StatusInternalServerError,
			fmt.Sprintf("Unable to retrieve statistics for the given issuer"))
	}
	issuerEECount.Issuer, err = db.GetCertByID(id)
	if err != nil {
		httpError(w, r, http.StatusInternalServerError,
			fmt.Sprintf("Could not retrieved stored certificate from database: %v", err))
		return
	}
	issuerEEData, err := json.Marshal(issuerEECount)
	if err != nil {
		httpError(w, r, http.StatusInternalServerError,
			fmt.Sprintf("Unable to marshal certificate IDs"))
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(issuerEEData)
	return
}

func jsonCertFromID(w http.ResponseWriter, r *http.Request, id int64) {
	val := r.Context().Value(ctxDBKey)
	if val == nil {
		httpError(w, r, http.StatusInternalServerError,
			fmt.Sprintf("Could not find database handler in request context"))
		return
	}
	db := val.(*pg.DB)
	cert, err := db.GetCertByID(id)
	if err != nil {
		httpError(w, r, http.StatusInternalServerError,
			fmt.Sprintf("Could not retrieved stored certificate from database: %v", err))
		return
	}

	certJson, err := json.Marshal(cert)
	if err != nil {
		httpError(w, r, http.StatusInternalServerError,
			fmt.Sprintf("Could not convert certificate to JSON: %v", err))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case "GET":
		w.WriteHeader(http.StatusOK)
	case "POST":
		w.WriteHeader(http.StatusCreated)
	}
	w.Write(certJson)
}

func StatsHandler(w http.ResponseWriter, r *http.Request) {
	var (
		stats pg.Statistics
		err   error
	)
	val := r.Context().Value(ctxDBKey)
	if val == nil {
		httpError(w, r, http.StatusInternalServerError,
			fmt.Sprintf("Could not find database handler in request context"))
		return
	}
	db := val.(*pg.DB)
	if r.FormValue("details") == "full" {
		stats.Scans, stats.Trusts, stats.Analyses, stats.Certificates, err = db.CountTableEntries()
		if err != nil {
			httpError(w, r, http.StatusInternalServerError, fmt.Sprintf("Failed to retrieve count of entries: %v", err))
			return
		}
		stats.PendingScans, err = db.CountPendingScans()
		if err != nil {
			httpError(w, r, http.StatusInternalServerError, fmt.Sprintf("Failed to retrieve count of pending scans: %v", err))
			return
		}
		stats.Last24HoursScans, err = db.CountLast24HoursScans()
		if err != nil {
			httpError(w, r, http.StatusInternalServerError, fmt.Sprintf("Failed to retrieve hourly count of scans over last 24 hours: %v", err))
			return
		}
		stats.TargetsLast24Hours, stats.DistinctTargetsLast24Hours, err = db.CountTargetsLast24Hours()
		if err != nil {
			httpError(w, r, http.StatusInternalServerError, fmt.Sprintf("Failed to retrieve count of distinct targets over last 24 hours: %v", err))
			return
		}
		stats.DistinctCertsSeenLast24Hours, err = db.CountDistinctCertsSeenLast24Hours()
		if err != nil {
			httpError(w, r, http.StatusInternalServerError, fmt.Sprintf("Failed to retrieve count of distinct certs seen over last 24 hours: %v", err))
			return
		}
		stats.DistinctCertsAddedLast24Hours, err = db.CountDistinctCertsAddedLast24Hours()
		if err != nil {
			httpError(w, r, http.StatusInternalServerError, fmt.Sprintf("Failed to retrieve count of distinct certs added over last 24 hours: %v", err))
			return
		}
		stats.ScansLast24Hours, err = db.CountScansLast24Hours()
		if err != nil {
			httpError(w, r, http.StatusInternalServerError, fmt.Sprintf("Failed to retrieve count of scans over last 24 hours: %v", err))
			return
		}
	} else {
		stats, err = db.GetLatestStatisticsFromView()
		if err != nil {
			httpError(w, r, http.StatusInternalServerError, fmt.Sprintf("Failed to retrieve latest statistics from materialized view: %v", err))
			return
		}
	}
	switch r.FormValue("format") {
	case "text":
		var buffer bytes.Buffer
		buffer.Write([]byte(fmt.Sprintf(`
Totals
-------------
scans:              %d
trust relations:    %d
analyses:           %d
certificates:       %d

Queue
-------------
pending scans:      %d

last 24 hours
-------------
- targets:          %d
- distinct targets: %d
- certs seen:       %d
- certs added:      %d
- scans:            %d
`, stats.Scans, stats.Trusts, stats.Analyses, stats.Certificates,
			stats.PendingScans, stats.TargetsLast24Hours, stats.DistinctTargetsLast24Hours,
			stats.DistinctCertsSeenLast24Hours, stats.DistinctCertsAddedLast24Hours,
			stats.ScansLast24Hours)))
		if r.FormValue("details") == "full" {
			buffer.Write([]byte(fmt.Sprintf(`
hourly scans
------------`)))

			for _, hsc := range stats.Last24HoursScans {
				buffer.Write([]byte(fmt.Sprintf("\n%s    %d", hsc.Hour.Format(time.RFC3339), hsc.Count)))
			}
		}
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		buffer.WriteTo(w)
	default:
		data, err := json.Marshal(stats)
		if err != nil {
			httpError(w, r, http.StatusInternalServerError, "Could not marshal statistics")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(data)
	}
}

func PreflightHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("preflighted"))
}

func heartbeatHandler(w http.ResponseWriter, r *http.Request) {
	val := r.Context().Value(ctxDBKey)
	if val == nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	db, ok := val.(*pg.DB)
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	var one uint
	err := db.QueryRow("SELECT 1").Scan(&one)
	if err != nil || one != 1 {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("alive"))
}

func versionHandler(w http.ResponseWriter, r *http.Request) {
	dir, err := os.Getwd()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	filename := path.Clean(dir + string(os.PathSeparator) + "version.json")
	f, err := os.Open(filename)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	stat, err := f.Stat()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	http.ServeContent(w, r, "__version__", stat.ModTime(), f)
}

func lbHeartbeatHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("alive"))
}

func HeartbeatHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("I iz alive."))
}

func validateDomain(domain string) bool {
	if domain == "" {
		return false
	}
	return true
}
