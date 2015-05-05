package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"sync"

	"certificate"
	"config"
	"modules/amqpmodule"
)

const rxQueue = "cert_analysis_queue"
const rxRoutKey = "cert_analysis"

var mozWildcards = [...]string{
	"*.mozilla.org",
	"*.mozilla.org",
	"*.firefox.com",
	"*.firefox.org",
}

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
	#    WildCard Certs Analyzer     #
	##################################
	`)
}

func hasWildcard(cert certificate.Certificate) bool {

	for _, s := range mozWildcards {
		for _, san := range cert.X509v3Extensions.SubjectAlternativeName {
			if san == s {
				return true
			}
		}
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

			if stored.CA {
				continue //we do not want to check CAs for wildcards
			}

			if hasWildcard(stored) {
				log.Printf("%s, with subjectCN: %s , is a wildcard mozilla cert.\n", stored.Hashes.SHA1, stored.Subject.CommonName)
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
