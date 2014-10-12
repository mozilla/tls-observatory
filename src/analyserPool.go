package main

import (
	"fmt"
	"log"
	"runtime"
	"sync"
	"encoding/base64"
	"crypto/x509"
	"crypto/sha1"

	"github.com/streadway/amqp"
	"github.com/mattbaird/elastigo/api"
	"github.com/mattbaird/elastigo/core"
)

func failOnError(err error, msg string) {
	if err != nil {
		log.Fatalf("%s: %s", msg, err)
		panic(fmt.Sprintf("%s: %s", msg, err))
	}
}

func SHA1Hash(data []byte) string {
	h := sha1.New()
	h.Write(data)
	return fmt.Sprintf("%X", h.Sum(nil))
}

func panicIf(err error) {
	if err != nil {
		panic(fmt.Sprintf("%s",err))
	}
}

func worker(msgs <-chan amqp.Delivery){

	forever := make(chan bool)
	defer wg.Done()

	for d := range msgs {
		var certif *x509.Certificate
    	data, err := base64.StdEncoding.DecodeString(string(d.Body))
    	panicIf(err)
		certif, err = x509.ParseCertificate(data)
		panicIf(err)
		// Index a doc using Structs
		_, err = core.Index("testindex", "user", SHA1Hash(certif.Raw), nil,`{"raw":"`+base64.StdEncoding.EncodeToString(certif.Raw)+`"}`)
		panicIf(err)
		d.Ack(false)
	}
		
	<-forever
}

var wg sync.WaitGroup


func main() {

	conn, err := amqp.Dial("amqp://guest:guest@localhost:5672/")
	failOnError(err, "Failed to connect to RabbitMQ")
	defer conn.Close()

	api.Domain = "83.212.99.104:9200"

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
		go worker(msgs)
    }

	wg.Wait()
}