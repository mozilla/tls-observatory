package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"time"

	"github.com/Sirupsen/logrus"

	"bytes"
	"crypto/sha256"
	"github.com/mozilla/tls-observatory/certificate"
	pg "github.com/mozilla/tls-observatory/database"
	"github.com/mozilla/tls-observatory/logger"
)

var scanRefreshRate float64

type scanResponse struct {
	ID int64 `json:"scan_id"`
}

// ScanHandler handles the /scans endpoint of the api
// It initiates new scans and returns created scans ids to be used against other endpoints.
func ScanHandler(w http.ResponseWriter, r *http.Request) {
	var (
		status int
		err    error
	)
	setResponseHeader(w)

	defer func() {
		if nil != err {
			http.Error(w, err.Error(), status)
		}
	}()

	log := logger.GetLogger()
	status = http.StatusInternalServerError

	log.WithFields(logrus.Fields{
		"form values": r.Form,
		"headers":     r.Header,
		"uri":         r.URL.RequestURI(),
	}).Debug("Scan endpoint received request")

	val := r.Context().Value(dbKey)
	if val == nil {
		log.Error("Could not find db in request context")
		err = errors.New("Could not access database.")
		return
	}

	db := val.(*pg.DB)

	domain := r.FormValue("target")
	if !validateDomain(domain) {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "")
	}

	rescan := false
	if r.FormValue("rescan") == "true" {
		rescan = true
	}

	previd, prevtime, err := db.GetLastScanTimeForTarget(domain)
	if err != nil {
		log.WithFields(logrus.Fields{
			"domain": domain,
			"error":  err.Error(),
		}).Error("Could not get last scan for target")
		err = errors.New("Could not get last scan for target")
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
	scan, err := db.NewScan(domain, -1) //no replay
	if err != nil {
		log.WithFields(logrus.Fields{
			"domain": domain,
			"error":  err.Error(),
		}).Error("Could not create new scan")
		err = errors.New("Could not create new scan")
		return
	}
	sr := scanResponse{
		ID: scan.ID,
	}
	respBody, err := json.Marshal(sr)
	if err != nil {
		log.WithFields(logrus.Fields{
			"scan_id": scan.ID,
			"error":   err.Error(),
		}).Error("Could not Marshal scan")

		err = errors.New("Could not process the requested scan")
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write(respBody)
	logRequest(r, http.StatusOK, len(respBody))
}

// ResultHandler handles the results endpoint of the api.
// It has a scan id as input and returns its results ( if available )
func ResultHandler(w http.ResponseWriter, r *http.Request) {
	var (
		status int
		err    error
	)
	setResponseHeader(w)

	defer func() {
		if nil != err {
			http.Error(w, err.Error(), status)
		}
	}()

	log := logger.GetLogger()
	status = http.StatusInternalServerError

	log.WithFields(logrus.Fields{
		"form values": r.Form,
		"headers":     r.Header,
		"uri":         r.URL.RequestURI(),
	}).Debug("Results endpoint received request")

	val := r.Context().Value(dbKey)
	if val == nil {
		log.Error("Could not find db in request context")
		err = errors.New("Could not access database.")
		return
	}

	db := val.(*pg.DB)

	idStr := r.FormValue("id")

	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		log.WithFields(logrus.Fields{
			"scan_id": idStr,
			"error":   err.Error(),
		}).Error("Could not parse scanid")
		err = errors.New("Could not parse provided scan id")
		status = http.StatusBadRequest
		return
	}

	scan, err := db.GetScanByID(id)
	if err != nil {
		log.WithFields(logrus.Fields{
			"scan_id": id,
			"error":   err.Error(),
		}).Error("Could not get scan from database")
		err = errors.New("Could not access database to get requested scan.")
		return
	}

	if scan.ID == -1 {
		log.WithFields(logrus.Fields{
			"scan_id": id,
		}).Debug("Did not find scan in database")

		err = errors.New("Could not find a scan with the id you provided.")
		status = http.StatusNotFound
		return
	}

	jsScan, err := json.Marshal(scan)
	if err != nil {
		log.WithFields(logrus.Fields{
			"scan_id": id,
			"error":   err.Error(),
		}).Error("Could not Marshal scan")

		err = errors.New("Could not process the requested scan")
		return
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, string(jsScan))
	logRequest(r, http.StatusOK, len(jsScan))
}

// CertificateHandler handles the /certificate endpoint of the api.
// It queries the database for the provided cert ids or sha256 and returns results in JSON.
func CertificateHandler(w http.ResponseWriter, r *http.Request) {
	var (
		err error
		id  int64
	)
	setResponseHeader(w)
	log := logger.GetLogger()
	log.WithFields(logrus.Fields{
		"form values": r.Form.Encode(),
		"headers":     r.Header,
		"uri":         r.URL.RequestURI(),
	}).Debug("Certificate Endpoint received request")

	val := r.Context().Value(dbKey)
	if val == nil {
		httpError(w, http.StatusInternalServerError, "Could not find database handler in request context")
		return
	}
	db := val.(*pg.DB)

	if r.FormValue("id") != "" {
		id, err = strconv.ParseInt(r.FormValue("id"), 10, 64)
		if err != nil {
			httpError(w, http.StatusBadRequest,
				fmt.Sprintf("Could not parse certificate id: %v", err))
			return
		}
	} else if r.FormValue("sha256") != "" {
		id, err = db.GetCertIDBySHA256Fingerprint(r.FormValue("sha256"))
		if err != nil {
			httpError(w, http.StatusInternalServerError,
				fmt.Sprintf("Could not retrieve certificate: %v", err))
			return
		}
	} else {
		httpError(w, http.StatusBadRequest, "Certificate ID or SHA256 are missing")
		return
	}
	jsonCertFromID(w, r, id)
	return
}

// PostCertificateHandler handles the POST /certificate endpoint of the api.
// It receives a single PEM encoded certificate, parses it, inserts it
// into the database and returns results in JSON.
func PostCertificateHandler(w http.ResponseWriter, r *http.Request) {
	setResponseHeader(w)
	log := logger.GetLogger()
	log.WithFields(logrus.Fields{
		"form values": r.Form.Encode(),
		"headers":     r.Header,
		"uri":         r.URL.RequestURI(),
	}).Debug("PostCertificate Endpoint received request")

	val := r.Context().Value(dbKey)
	if val == nil {
		httpError(w, http.StatusInternalServerError, "Could not find database handler in request context")
		return
	}
	db := val.(*pg.DB)

	_, certHeader, err := r.FormFile("certificate")
	if err != nil {
		httpError(w, http.StatusBadRequest,
			fmt.Sprintf("Could not read certificate from form data: %v", err))
		return
	}

	certReader, err := certHeader.Open()
	if err != nil {
		httpError(w, http.StatusBadRequest,
			fmt.Sprintf("Could not read certificate from form data: %v", err))
		return
	}

	certPEM, err := ioutil.ReadAll(certReader)
	if err != nil {
		httpError(w, http.StatusBadRequest,
			fmt.Sprintf("Could not read certificate from form data: %v", err))
		return
	}

	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		httpError(w, http.StatusBadRequest,
			"Failed to parse certificate PEM")
		return
	}

	certX509, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		httpError(w, http.StatusBadRequest,
			fmt.Sprintf("Could not parse X.509 certificate: %v", err))
		return
	}

	certHash := certificate.SHA256Hash(certX509.Raw)
	id, err := db.GetCertIDBySHA256Fingerprint(certHash)
	if err != nil {
		httpError(w, http.StatusInternalServerError,
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
		httpError(w, http.StatusInternalServerError,
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
		httpError(w, http.StatusInternalServerError,
			fmt.Sprintf("Failed to retrieve chains from database: %v", err))
		return
	}
	for _, parent := range paths.Parents {
		cert.ValidationInfo = parent.GetValidityMap()
		_, err := db.InsertTrustToDB(cert, cert.ID, parent.Cert.ID)
		if err != nil {
			httpError(w, http.StatusInternalServerError,
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
	setResponseHeader(w)
	log := logger.GetLogger()
	log.WithFields(logrus.Fields{
		"form values": r.Form.Encode(),
		"headers":     r.Header,
		"uri":         r.URL.RequestURI(),
	}).Debug("Paths Endpoint received request")

	val := r.Context().Value(dbKey)
	if val == nil {
		httpError(w, http.StatusInternalServerError, "Could not find database handler in request context")
		return
	}
	db := val.(*pg.DB)

	if r.FormValue("id") != "" {
		id, err = strconv.ParseInt(r.FormValue("id"), 10, 64)
		if err != nil {
			httpError(w, http.StatusBadRequest,
				fmt.Sprintf("Could not parse certificate id: %v", err))
			return
		}
	} else if r.FormValue("sha256") != "" {
		id, err = db.GetCertIDBySHA256Fingerprint(r.FormValue("sha256"))
		if err != nil {
			httpError(w, http.StatusInternalServerError,
				fmt.Sprintf("Could not retrieve certificate: %v", err))
			return
		}
	} else {
		httpError(w, http.StatusBadRequest, "Certificate ID or SHA256 are missing")
		return
	}
	cert, err := db.GetCertByID(id)
	if err != nil {
		httpError(w, http.StatusInternalServerError,
			fmt.Sprintf("Could not retrieved stored certificate from database: %v", err))
		return
	}
	paths, err := db.GetCertPaths(cert)
	if err != nil {
		httpError(w, http.StatusInternalServerError,
			fmt.Sprintf("Failed to retrieve certificate paths from database: %v", err))
		return
	}
	pathsJson, err := json.Marshal(paths)
	if err != nil {
		httpError(w, http.StatusInternalServerError,
			fmt.Sprintf("Could not convert certificate paths to JSON: %v", err))
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write(pathsJson)
	logRequest(r, http.StatusOK, len(pathsJson))
	return
}

// TruststoreHandler handles the /truststore endpoint of the api.
// It queries the database for all certificates trusted by a certain program.
// It takes the following parameters as HTTP query parameters:
//     store: one of {"mozilla", "android", "apple", "microsoft", "ubuntu"}
//     format: one of {"json", "pem"}
func TruststoreHandler(w http.ResponseWriter, r *http.Request) {
	setResponseHeader(w)
	log := logger.GetLogger()
	log.WithFields(logrus.Fields{
		"form values": r.Form.Encode(),
		"headers":     r.Header,
		"uri":         r.URL.RequestURI(),
	}).Debug("Truststore Endpoint received request")

	val := r.Context().Value(dbKey)
	if val == nil {
		httpError(w, http.StatusInternalServerError, "Could not find database handler in request context")
		return
	}
	db := val.(*pg.DB)
	certs, err := db.GetAllCertsInStore(r.FormValue("store"))
	if err == pg.ErrInvalidCertStore {
		httpError(w, http.StatusBadRequest, fmt.Sprintf("Invalid certificate trust store provided: %s", r.FormValue("store")))
		return
	} else if err != nil {
		logrus.Error("Error querying truststore:", err)
		httpError(w, http.StatusBadRequest, "Error querying trust store")
		return
	}
	switch r.FormValue("format") {
	case "json":
		certsJSON, err := json.Marshal(certs)
		if err != nil {
			httpError(w, http.StatusInternalServerError, "Could not marshal certificates")
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		w.Write(certsJSON)
		logRequest(r, http.StatusOK, len(certsJSON))
	case "pem":
		var buffer bytes.Buffer
		for _, cert := range certs {
			x509, err := cert.ToX509()
			if err != nil {
				httpError(w, http.StatusInternalServerError, "Could not convert certificate to X509")
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
				httpError(w, http.StatusInternalServerError, "Error PEM-encoding certificate")
				return
			}
		}
		bufferLen := buffer.Len()
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		buffer.WriteTo(w)
		logRequest(r, http.StatusOK, bufferLen)
	default:
		httpError(w, http.StatusBadRequest, "Invalid output format")
	}
}

func jsonCertFromID(w http.ResponseWriter, r *http.Request, id int64) {
	val := r.Context().Value(dbKey)
	if val == nil {
		httpError(w, http.StatusInternalServerError, "Could not find database handler in request context")
		return
	}
	db := val.(*pg.DB)
	cert, err := db.GetCertByID(id)
	if err != nil {
		httpError(w, http.StatusInternalServerError,
			fmt.Sprintf("Could not retrieved stored certificate from database: %v", err))
		return
	}

	certJson, err := json.Marshal(cert)
	if err != nil {
		httpError(w, http.StatusInternalServerError,
			fmt.Sprintf("Could not convert certificate to JSON: %v", err))
		return
	}
	switch r.Method {
	case "GET":
		w.WriteHeader(http.StatusOK)
		logRequest(r, http.StatusOK, len(certJson))
	case "POST":
		w.WriteHeader(http.StatusCreated)
		logRequest(r, http.StatusCreated, len(certJson))
	}
	w.Write(certJson)
}

func PreflightHandler(w http.ResponseWriter, r *http.Request) {
	setResponseHeader(w)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("preflighted"))
}

func HeartbeatHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("I iz alive."))
}

func setResponseHeader(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS, POST")
	w.Header().Set("Access-Control-Max-Age", "86400")
	w.Header().Set("Content-Type", "application/json")
}

func validateDomain(domain string) bool {
	if domain == "" {
		return false
	}
	return true
}
