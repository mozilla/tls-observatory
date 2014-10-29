package main

import (
	"github.com/gorilla/mux"
	"github.com/streadway/amqp"
	"log"
	"net/http"
	"fmt"
)

func main() {
	r := mux.NewRouter()

	// try to filter files to download, example only
	r.HandleFunc("/website/{domain}", DownloadHandler)

	//-
	http.Handle("/", r)

	// wait for clients
	http.ListenAndServe(":8083", nil)
}

func failOnError(err error, msg string) {
	if err != nil {
		log.Fatalf("%s: %s", msg, err)
		panic(fmt.Sprintf("%s: %s", msg, err))
	}
}

func DownloadHandler(res http.ResponseWriter, req *http.Request) {

	var (
		status int
		err    error
	)

	defer func() {
		if nil != err {
			http.Error(res, err.Error(), status)
		}
	}()

	vars := mux.Vars(req)
	domain := vars["domain"]

	fmt.Print(domain)

	if validateDomain(domain){

		conn, err := amqp.Dial("amqp://guest:guest@localhost:5672/")
		failOnError(err, "Failed to connect to RabbitMQ")
		defer conn.Close()

		ch, err := conn.Channel()
		failOnError(err, "Failed to open a channel")
		defer ch.Close()

		status = http.StatusOK
		err = ch.Publish(
		"",           // exchange
		"scan_ready_queue", // routing key
		false,        // mandatory
		false,
		amqp.Publishing{
			DeliveryMode: amqp.Persistent,
			ContentType:  "text/plain",
			Body:         []byte(domain),
		})

		
	}else{
		status = http.StatusBadRequest
		return
	}

}

func validateDomain( domain string ) ( bool ){

	// TODO
	// Need to validate the domain, in a way,
	// before passing it to the retriever queue

	return true
}