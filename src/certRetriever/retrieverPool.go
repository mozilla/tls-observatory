package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"runtime"

	"config"
	"tlsretriever"

	"github.com/streadway/amqp"
)

func failOnError(err error, msg string) {
	if err != nil {
		log.Fatalf("%s: %s", msg, err)
		panic(fmt.Sprintf("%s: %s", msg, err))
	}
}

func panicIf(err error) {
	if err != nil {
		log.Println(fmt.Sprintf("%s", err))
	}
}

type CertChain struct {
	Domain string   `json:"domain"`
	IP     string   `json:"ip"`
	Certs  []string `json:"certs"`
}

func releaseSemaphore() {
	sem <- true
}

func worker(msg []byte, ch *amqp.Channel) {

	log.Println("waiting for channel")
	<-sem
	defer releaseSemaphore()
	log.Println("arrived")

	certs, ip, err := tlsretriever.CheckHost(string(msg), "443", true)
	panicIf(err)
	if certs == nil {
		log.Println("no certificate retrieved from", string(msg))
		return
	}

	var chain = CertChain{}

	chain.Domain = string(msg)

	chain.IP = ip

	for _, cert := range certs {

		chain.Certs = append(chain.Certs, base64.StdEncoding.EncodeToString(cert.Raw))

	}

	jsonChain, er := json.MarshalIndent(chain, "", "    ")
	panicIf(er)
	err = ch.Publish(
		"",                   // exchange
		"scan_results_queue", // routing key
		false,                // mandatory
		false,
		amqp.Publishing{
			DeliveryMode: amqp.Persistent,
			ContentType:  "text/plain",
			Body:         []byte(jsonChain),
		})
	panicIf(err)
}

var sem chan bool

func main() {

	conf := config.ObserverConfig{}

	var er error
	conf, er = config.ConfigLoad("observer.cfg")

	if er != nil {
		panicIf(er)
		conf = config.GetDefaults()
	}

	conn, err := amqp.Dial(conf.General.RabbitMQRelay)
	failOnError(err, "Failed to connect to RabbitMQ")
	defer conn.Close()

	ch, err := conn.Channel()
	failOnError(err, "Failed to open a channel")
	defer ch.Close()

	q, err := ch.QueueDeclare(
		"scan_ready_queue", // name
		true,               // durable
		false,              // delete when unused
		false,              // exclusive
		false,              // no-wait
		nil,                // arguments
	)
	failOnError(err, "Failed to declare a queue")

	//In case it has not already been declared before...
	_, err = ch.QueueDeclare(
		"scan_results_queue", // name
		true,                 // durable
		false,                // delete when unused
		false,                // exclusive
		false,                // no-wait
		nil,                  // arguments
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
		true,   // auto-ack
		false,  // exclusive
		false,  // no-local
		false,  // no-wait
		nil,    // args
	)
	failOnError(err, "Failed to register a consumer")

	cores := runtime.NumCPU()
	runtime.GOMAXPROCS(cores)

	maxSimConnections := conf.General.MaxSimConns

	//use channels as semaphores not to exhaust file descriptors
	sem = make(chan bool, maxSimConnections)
	for i := 0; i < maxSimConnections; i++ {
		sem <- true
	}

	for d := range msgs {
		go worker(d.Body, ch)
	}
}
