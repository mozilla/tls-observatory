package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/Sirupsen/logrus"
	"github.com/gorilla/context"

	"github.com/mozilla/tls-observatory/certificate"
	pg "github.com/mozilla/tls-observatory/database"
	"github.com/mozilla/tls-observatory/logger"
)

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

	log := logger.GetLogger()

	log.WithFields(logrus.Fields{
		"form values": r.Form,
		"headers":     r.Header,
	}).Debug("Received request")

	val, ok := context.GetOk(r, dbKey)
	if !ok {
		log.Error("Could not find db in request context")
		err = errors.New("Could not access database.")
		return
	}

	db := val.(*pg.DB)

	domain := r.FormValue("target")

	if validateDomain(domain) {

		scan, err := db.NewScan(domain, -1) //no replay
		if err != nil {
			log.WithFields(logrus.Fields{
				"domain": domain,
				"error":  err.Error(),
			}).Error("Could not create new scan")
			err = errors.New("Could not create new scan")
			return
		}

		resp := fmt.Sprintf(`{"scan_id":"%d"}`, scan.ID)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, resp)
	} else {
		w.WriteHeader(http.StatusBadRequest)
	}
}

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
	}).Debug("Received request")

	val, ok := context.GetOk(r, dbKey)
	if !ok {
		log.Error("Could not find db in request context")
		err = errors.New("Could not access database.")
		return
	}

	db := val.(*pg.DB)

	scanIDStr := r.FormValue("scan_id")

	scanID, err := strconv.ParseInt(scanIDStr, 10, 64)

	if err != nil {
		log.WithFields(logrus.Fields{
			"scan_id": scanIDStr,
			"error":   err.Error(),
		}).Error("Could not parse scanid")
		err = errors.New("Something went wrong :\\")
		return
	}

	scan, err := db.GetScan(scanID)

	if err != nil {
		log.WithFields(logrus.Fields{
			"scan_id": scanIDStr,
			"error":   err.Error(),
		}).Error("Could not get scan from database")

		err = errors.New("Something went wrong :\\")
		return
	}

	if scan.ID == -1 {
		log.WithFields(logrus.Fields{
			"scan_id": scanIDStr,
		}).Debug("Did not find scan in database")

		err = errors.New("Could not find a scan with the id you provided")
		status = http.StatusNotFound
		return
	}

	jsScan, err := json.MarshalIndent(scan, "", "	")

	if err != nil {
		log.WithFields(logrus.Fields{
			"scan_id": scanIDStr,
			"error":   err.Error(),
		}).Error("Could not Marshal scan")

		err = errors.New("Something went wrong :\\")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, string(jsScan))
}

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
	}).Debug("Received request")

	val, ok := context.GetOk(r, dbKey)

	if !ok {
		log.Error("Could not find db in request context")
		err = errors.New("Could not access database.")
		return
	}

	db := val.(*pg.DB)

	certIDstr := r.FormValue("cert_id")

	certID, err := strconv.ParseInt(certIDstr, 10, 64)

	if err != nil {
		log.WithFields(logrus.Fields{
			"scan_id": certID,
			"error":   err.Error(),
		}).Error("Could not parse scanid")
		err = errors.New("Something went wrong :\\")
		return
	}

	certificate.SetDB(db)

	cert, err := certificate.GetCertwithID(certID)

	if err != nil {
		log.WithFields(logrus.Fields{
			"scan_id": certID,
			"error":   err.Error(),
		}).Error("Could not get cert from database")

		err = errors.New("Something went wrong :\\")
		return
	}

	jsScan, err := json.MarshalIndent(cert, "", "	")

	if err != nil {
		log.WithFields(logrus.Fields{
			"cert_id": certID,
			"error":   err.Error(),
		}).Error("Could not Marshal cert")

		err = errors.New("Something went wrong :\\")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, string(jsScan))
}

func validateDomain(domain string) bool {

	// TODO
	// Need to validate the domain, in a way,
	// before passing it to the retriever queue

	return true
}
