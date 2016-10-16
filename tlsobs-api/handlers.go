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
	w.WriteHeader(http.StatusCreated)
	w.Write(certJson)
}

func PreflightHandler(w http.ResponseWriter, r *http.Request) {
	setResponseHeader(w)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("preflighted"))
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
