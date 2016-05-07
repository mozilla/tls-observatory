package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/gorilla/context"

	pg "github.com/mozilla/tls-observatory/database"
	"github.com/mozilla/tls-observatory/logger"
)

var scanRefreshRate float64

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

	log := logger.GetLogger()
	status = http.StatusInternalServerError

	log.WithFields(logrus.Fields{
		"form values": r.Form,
		"headers":     r.Header,
	}).Debug("Scan endpoint received request")

	val, ok := context.GetOk(r, dbKey)
	if !ok {
		log.Error("Could not find db in request context")
		err = errors.New("Could not access database.")
		return
	}

	db := val.(*pg.DB)

	domain := r.FormValue("target")
	if validateDomain(domain) {

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
					resp := fmt.Sprintf(`{"scan_id":"%d"}`, previd)
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					fmt.Fprint(w, resp)
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

		resp := fmt.Sprintf(`{"scan_id":%d}`, scan.ID)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, resp)
	} else {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "")
	}
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

	log := logger.GetLogger()
	status = http.StatusInternalServerError

	log.WithFields(logrus.Fields{
		"form values": r.Form,
		"headers":     r.Header,
	}).Debug("Results endpoint received request")

	val, ok := context.GetOk(r, dbKey)
	if !ok {
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

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, string(jsScan))
}

// CertificateHandler handles the /certificate endpoint of the api.
// It queries the database for the provided cert ids and returns results in JSON.
func CertificateHandler(w http.ResponseWriter, r *http.Request) {

	var (
		status int
		err    error
	)

	defer func() {
		if nil != err {
			http.Error(w, err.Error(), status)
		}
	}()

	log := logger.GetLogger()
	status = http.StatusInternalServerError

	log.WithFields(logrus.Fields{
		"form values": r.Form.Encode(),
		"headers":     r.Header,
	}).Debug("Certificate Endpoint received request")

	val, ok := context.GetOk(r, dbKey)
	if !ok {
		log.Error("Could not find db in request context")
		err = errors.New("Could not access database.")
		return
	}

	db := val.(*pg.DB)

	idStr := r.FormValue("id")

	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		log.WithFields(logrus.Fields{
			"cert_id": id,
			"error":   err.Error(),
		}).Error("Could not parse certificate id")

		status = http.StatusBadRequest
		err = errors.New("Could not parse provided certificate id")
		return
	}

	cert, err := db.GetCertByID(id)
	if err != nil {
		log.WithFields(logrus.Fields{
			"cert_id": id,
			"error":   err.Error(),
		}).Error("Could not get cert from database")

		err = errors.New("Could not access database to get requested certificate")
		return
	}

	jsScan, err := json.Marshal(cert)
	if err != nil {
		log.WithFields(logrus.Fields{
			"cert_id": id,
			"error":   err.Error(),
		}).Error("Could not Marshal cert")

		err = errors.New("Could not process requested certificate")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, string(jsScan))
}

func validateDomain(domain string) bool {
	if domain == "" {
		return false
	}
	return true
}
