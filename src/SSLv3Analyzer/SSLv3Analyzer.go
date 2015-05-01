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

	"config"
	"connection"
	"modules/amqpmodule"
)

const rxQueue = "conn_analysis_queue"
const rxRoutKey = "conn_analysis"
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
	#         SSLv3 Analyzer          #
	##################################
	`)
}

func hasSSLv3(c connection.Stored) bool {
	for _, s := range c.CipherSuites {
		for _, p := range s.Protocols {
			if p == "SSLv3" {
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

		stored := connection.Stored{}

		err := json.Unmarshal(d, &stored)
		panicIf(err)

		if err == nil {

			if hasSSLv3(stored) {
				log.Printf("Scan Target %s has SSLv3 protocol available.", stored.ScanTarget)
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
