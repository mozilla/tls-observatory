package main

import (
	"fmt"
	"log"
	"runtime"
	"sync"
	"encoding/base64"
	"crypto/x509"
	"database/sql"


	"github.com/streadway/amqp"
	_ "github.com/lib/pq"
)

func failOnError(err error, msg string) {
	if err != nil {
		log.Fatalf("%s: %s", msg, err)
		panic(fmt.Sprintf("%s: %s", msg, err))
	}
}

func panicIf(err error) {
	if err != nil {
		panic(fmt.Sprintf("%s",err))
	}
}

func worker(msgs <-chan amqp.Delivery, db *sql.DB){

	forever := make(chan bool)
	defer wg.Done()

	for d := range msgs {
		var certif *x509.Certificate
    	data, err := base64.StdEncoding.DecodeString(string(d.Body))
    	panicIf(err)
		certif, err = x509.ParseCertificate(data)
		panicIf(err)
		db.Exec("insert into t(b) values($1)", base64.StdEncoding.EncodeToString(certif.Raw))
	}
		
	<-forever
}

var wg sync.WaitGroup


func main() {

	conn, err := amqp.Dial("amqp://guest:guest@localhost:5672/")
	failOnError(err, "Failed to connect to RabbitMQ")
	defer conn.Close()

	db, err := sql.Open("postgres", "user=tlsobsadmin dbname=tlsobs host=tlsobservatory.chrnadvfyed4.eu-west-1.rds.amazonaws.com password=rGjg7ytrZKyZuf8Swq9gvawPVVQKyxhn")
	failOnError(err, "Failed to open DB")

	ch, err := conn.Channel()
	failOnError(err, "Failed to open a channel")
	defer ch.Close()

	q, err := ch.QueueDeclare(
		"scan_results_queue", // name
		true,         // durable
		false,        // delete when unused
		false,        // exclusive
		false,        // no-wait
		nil,          // arguments
	)
	failOnError(err, "Failed to declare a queue")

	err = ch.Qos(
		3,     // prefetch count
		0,     // prefetch size
		false, // global
	)

	failOnError(err, "Failed to set QoS")

	msgs, err := ch.Consume(
		q.Name, // queue
		"",     // consumer
		false,  // auto-ack
		false,  // exclusive
		false,  // no-local
		false,  // no-wait
		nil,    // args
	)

	failOnError(err, "Failed to register a consumer")

	cores := runtime.NumCPU()
	runtime.GOMAXPROCS(cores)

	for i := 0; i < cores; i++ {
        wg.Add(1)
		go worker(msgs,db)
    }

	wg.Wait()
}