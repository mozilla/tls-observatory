package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/mozilla/TLS-Observer/src/certificate"
	"github.com/mozilla/TLS-Observer/src/config"
	"github.com/mozilla/TLS-Observer/src/modules/amqpmodule"
)

const rxQueue = "cert_analysis_queue"
const rxRoutKey = "cert_analysis"
const thirtyNineMonths = time.Duration(28512 * time.Hour)

var broker *amqpmodule.Broker
var wg sync.WaitGroup

func failOnError(err error, msg string) {
	if err != nil {
		log.Fatalf("%s: %s", msg, err)
		panic(fmt.Sprintf("%s: %s", msg, err))
	}
}

func panicIf(err error) bool {
	if err != nil {
		log.Println(fmt.Sprintf("%s", err))
		return true
	}

	return false
}

func printIntro() {
	fmt.Println(`
	##################################
	#         39Mo Analyzer          #
	##################################
	`)
}

func isValidmorethan39(cert certificate.Certificate) bool {
	na, err := time.Parse("2006-01-02 15:04:05 +0000 UTC", cert.Validity.NotAfter)
	if err != nil {
		panic(err)
	}
	nb, err := time.Parse("2006-01-02 15:04:05 +0000 UTC", cert.Validity.NotBefore)
	if err != nil {
		panic(err)
	}
	if na.Sub(nb) > thirtyNineMonths {
		return true
	}

	return false
}

//worker is the main body of the goroutine that handles each received message.
func worker(msgs <-chan []byte) {

	forever := make(chan bool)
	defer wg.Done()

	for d := range msgs {

		stored := certificate.Certificate{}

		err := json.Unmarshal(d, &stored)
		panicIf(err)

		if err != nil {
			if isValidmorethan39(stored) {
				log.Printf("%s, with subjectCN: %s , is valid for more than 39 mo. Is CA: %t \n", stored.Hashes.SHA1, stored.Subject.CommonName, stored.CA)
				//TODO:Mozdef publishing code goes here.
			}
		}
	}

	<-forever
}

func main() {
	var (
		err error
	)

	printIntro()

	conf := config.AnalyzerConfig{}

	var cfgFile string
	flag.StringVar(&cfgFile, "c", "/etc/observer/analyzer.cfg", "Input file csv format")
	flag.Parse()

	_, err = os.Stat(cfgFile)
	failOnError(err, "Missing configuration file from '-c' or /etc/observer/retriever.cfg")

	conf, err = config.AnalyzerConfigLoad(cfgFile)
	if err != nil {
		conf = config.GetAnalyzerDefaults()
	}

	cores := runtime.NumCPU()
	runtime.GOMAXPROCS(cores * conf.General.GoRoutines)

	broker, err = amqpmodule.RegisterURL(conf.General.RabbitMQRelay)

	failOnError(err, "Failed to register RabbitMQ")

	msgs, err := broker.Consume(rxQueue, rxRoutKey)

	if err != nil {
		failOnError(err, "Failed to Consume from receiving queue")
	}

	for i := 0; i < cores; i++ {
		wg.Add(1)
		go worker(msgs)
	}

	wg.Wait()
}
