package main

import (
	"github.com/streadway/amqp"
	"log"
	"net/http"
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

	domain := r.FormValue("target")

	if validateDomain(domain) {

		conn, err := amqp.Dial("amqp://guest:guest@localhost:5672/")
		if err != nil {
			log.Fatal(err)
		}
		defer conn.Close()

		ch, err := conn.Channel()
		if err != nil {
			log.Fatal(err)
		}
		defer ch.Close()

		status = http.StatusOK

		log.Println("Publishing", domain)
		err = ch.Publish(
			"amq.direct", // exchange
			"scan_ready", // routing key
			false,        // mandatory
			false,
			amqp.Publishing{
				DeliveryMode: amqp.Persistent,
				ContentType:  "text/plain",
				Body:         []byte(domain),
			})

	} else {
		status = http.StatusBadRequest
		return
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

	domain := r.FormValue("target")

	if validateDomain(domain) {

		status = http.StatusOK

	} else {
		status = http.StatusBadRequest
		return
	}

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

	domain := r.FormValue("target")

	if validateDomain(domain) {

		raw := r.FormValue("raw")

		rawCert := false

		if raw == "true" {
			rawCert = true
		}

		log.Println("rawCert:", rawCert)

		status = http.StatusOK

	} else {
		status = http.StatusBadRequest
		return
	}

}

func validateDomain(domain string) bool {

	// TODO
	// Need to validate the domain, in a way,
	// before passing it to the retriever queue

	return true
}
