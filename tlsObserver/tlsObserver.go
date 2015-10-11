package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"time"

	"github.com/mozilla/TLS-Observer/certificate"
	"github.com/mozilla/TLS-Observer/config"
	"github.com/mozilla/TLS-Observer/connection"
	"github.com/mozilla/TLS-Observer/modules/amqpmodule"
	"github.com/mozilla/TLS-Observer/worker"
)

type Scan struct {
	id               string
	time_stamp       time.Time
	target           string
	replay           int //hours or days
	has_tls          bool
	cert_id          string
	is_valid         bool
	validation_error string
	is_ubuntu_valid  bool
	is_mozilla_valid bool
	is_windows_valid bool
	is_apple_valid   bool
	conn_info        []byte
}

const rxQueue = "cert_rx_queue"
const rxRoutKey = "scan_ready"

var broker *amqpmodule.Broker

func failOnError(err error, msg string) {
	if err != nil {
		log.Fatalf("%s: %s", msg, err)
		panic(fmt.Sprintf("%s: %s", msg, err))
	}
}

func main() {
	var err error

	conf := config.ObserverConfig{}

	var cfgFile string
	flag.StringVar(&cfgFile, "c", "/etc/observer/observer.cfg", "Input file csv format")
	flag.Parse()

	_, err = os.Stat(cfgFile)
	failOnError(err, "Missing configuration file from '-c' or /etc/observer/observer.cfg")

	conf, err = config.ObserverConfigLoad(cfgFile)
	if err != nil {
		conf = config.GetObserverDefaults()
	}

	cores := runtime.NumCPU()
	runtime.GOMAXPROCS(cores * conf.General.GoRoutines)

	broker, err = amqpmodule.RegisterURL(conf.General.RabbitMQRelay)

	failOnError(err, "Failed to register RabbitMQ")

	msgs, err := broker.Consume(rxQueue, rxRoutKey)

	for d := range msgs {

		go func(id []byte) {

			scan := getScan(string(id))

			resChan := make(chan worker.WorkerResult)
			defer close(resChan)

			go func() {
				certID, jsonCert, err := certificate.HandleCert(scan.target)
				err, ok := err.(certificate.NoTLSCertsErr)

				if ok {
					//nil cert, does not implement TLS
				}

			}()
			//run connection go routine
			go func() {
				js, err := connection.Connect(scan.target)
			}()

			go func() {
				for name, wrkInfo := range worker.AvailableWorkers {

					go wrkInfo.Runner.(worker.Worker).Run([]byte(scan.target), resChan)
				}
			}()

			timeout := make(chan bool, 1)
			go func() {
				time.Sleep(10 * time.Second)
				timeout <- true
			}()

			select {
			case <-timeout:
			//wait no more than 10 secs for all workers to finish.

			case <-resChan:

			}

		}(d)
	}

	select {}
}

func getScan(id string) Scan {

	s := Scan{}
	return s

}
