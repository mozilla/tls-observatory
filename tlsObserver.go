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
	pg "github.com/mozilla/TLS-Observer/modules/postgresmodule"
	"github.com/mozilla/TLS-Observer/worker"
)

const rxQueue = "cert_rx_queue"
const rxRoutKey = "scan_ready"

var broker *amqpmodule.Broker
var db *pg.DB

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

	db, err = pg.RegisterConnection("observer", "observer", conf.General.PostgresPass, conf.General.Postgres, "disable")

	failOnError(err, "Failed to connect to database")

	broker, err = amqpmodule.RegisterURL(conf.General.RabbitMQRelay)

	failOnError(err, "Failed to register RabbitMQ")

	msgs, err := broker.Consume(rxQueue, rxRoutKey)

	certificate.Setup(conf,db)

	for d := range msgs {

		go func(id []byte) {

			tx, err := db.Begin()

			if err != nil {
				log.Println(err)
				return
			}

			scan, err := db.GetScan(string(id))

			if err != nil {
				log.Println(err, "Could not find /decode scan with id: ", string(id))
				tx.Rollback()
				return
			}

			totalWorkers := len(worker.AvailableWorkers)

			resChan := make(chan worker.WorkerResult)
			defer close(resChan)

			go func() {
				certID, jsonCert, err := certificate.HandleCert(scan.Target)
				err, ok := err.(certificate.NoTLSCertsErr)

				if ok {
					//nil cert, does not implement TLS
					tx.Rollback()
					//update scans table
					return
				}

				//Update scans table
				//TODO start second stage workers requiring certificate

			}()
			//run connection go routine
			go func() {
				js, err := connection.Connect(scan.Target)

			}()

			go func() {
				for name, wrkInfo := range worker.AvailableWorkers {

					go wrkInfo.Runner.(worker.Worker).Run([]byte(scan.Target), resChan)
				}
			}()

			timeout := make(chan bool, 1)
			go func() {
				time.Sleep(10 * time.Second)
				timeout <- true
			}()

			endedWorkers := 0
			select {
			case <-timeout:
				err := tx.Commit()
				return
				//wait no more than 10 secs for all workers to finish.

			case <-resChan:
				endedWorkers += endedWorkers
				currCompletionPercentage := ((endedWorkers/totalWorkers)*80 + 20) / 100
				
				db.
				//write worker result to db
				//update completion percentage in db
			}

		}(d)
	}

	select {}
}
