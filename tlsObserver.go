package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"strconv"
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

	conf := config.ObserverConfig{}

	var cfgFile, cipherscan string
	flag.StringVar(&cfgFile, "c", "/etc/observer/observer.cfg", "Input file csv format")
	flag.StringVar(&cipherscan, "b", "/etc/observer/cipherscan/cipherscan", "Cipherscan binary location")
	flag.Parse()

	_, err := os.Stat(cfgFile)
	failOnError(err, "Missing configuration file from '-c' or /etc/observer/observer.cfg")

	_, err = os.Stat(cipherscan)
	if err != nil {
		log.Println("Could not locate cipherscan binary in ", cipherscan, ".")
		log.Println("TLS Connection capabilities are not available.")
	}

	conf, err = config.ObserverConfigLoad(cfgFile)
	if err != nil {
		conf = config.GetObserverDefaults()
	}

	cores := runtime.NumCPU()
	runtime.GOMAXPROCS(cores * conf.General.GoRoutines)

	db, err = pg.RegisterConnection(conf.General.PostgresDB, conf.General.PostgresUser, conf.General.PostgresPass, conf.General.Postgres, "disable")

	failOnError(err, "Failed to connect to database")

	broker, err = amqpmodule.RegisterURL(conf.General.RabbitMQRelay)

	failOnError(err, "Failed to register RabbitMQ")

	msgs, err := broker.Consume(rxQueue, rxRoutKey)

	certificate.Setup(conf, db)

	for d := range msgs {

		log.Println("Received id : ", string(d))

		go func(id []byte) {

			tx, err := db.Begin()

			if err != nil {
				log.Println(err)
				return
			}

			intID, err := strconv.ParseInt(string(id), 10, 64)

			scan, err := db.GetScan(intID)

			if err != nil {
				log.Println(err, "Could not find/decode scan with id: ", string(id))
				tx.Rollback()
				return
			}

			totalWorkers := len(worker.AvailableWorkers)

			resChan := make(chan worker.WorkerResult)

			go func() {

				certID, trustID, err := certificate.HandleCert(scan.Target)

				if err != nil {

					err, ok := err.(certificate.NoTLSCertsErr)

					if ok {
						//nil cert, does not implement TLS
						tx.Rollback()

						db.Exec("UPDATE scans SET has_tls=FALSE WHERE id=$1", intID)
						return
					} else {
						log.Println(err)
						tx.Rollback()
					}

				}

				log.Println("Retrieved certs ", certID, trustID)

				log.Println("Updating scans")
				_, err = db.Exec("UPDATE scans SET cert_id=$1,trust_id=$2,has_tls=TRUE WHERE id=$3", certID, trustID, intID)

				if err != nil {
					log.Println("Could not update scans for cert, ", err.Error())
				}

				err = db.UpdateScanCompletionPercentage(intID, 20)
				if err != nil {
					log.Println("Could not update completion percentage for scan :", string(id))
				}
				//TODO start second stage workers requiring certificate

			}()
			//run connection go routine
			go func() {

				js, err := connection.Connect(scan.Target, cipherscan)

				if err != nil {

					err, ok := err.(connection.NoTLSConnErr)

					if ok {
						//does not implement TLS
						tx.Rollback()

						db.Exec("UPDATE scans SET has_tls=FALSE WHERE id=$1", intID)
						return
					} else {
						log.Println(err)
						tx.Rollback()
					}

				} else {
					db.Exec("UPDATE scans SET conn_info=$1 WHERE id=$2", js, intID)
				}

			}()

			go func() {
				for _, wrkInfo := range worker.AvailableWorkers {

					go wrkInfo.Runner.(worker.Worker).Run([]byte(scan.Target), resChan)
				}
			}()

			timeout := make(chan bool, 1)
			go func() {
				time.Sleep(10 * time.Second)
				timeout <- true
			}()

			if totalWorkers > 0 {
				endedWorkers := 0
				select {

				case <-timeout:

					log.Println("Timed out...")
					err := tx.Commit()

					if err != nil {
						log.Println(err)
					}
					return
					//wait no more than 10 secs for all workers to finish.

				case res := <-resChan:
					endedWorkers += endedWorkers
					currCompletionPercentage := ((endedWorkers/totalWorkers)*80 + 20)

					err = db.UpdateScanCompletionPercentage(intID, currCompletionPercentage)
					if err != nil {
						log.Println("Could not update completion percentage for scan :", string(id))
					}

					if res.Success {
						tx.Exec("INSERT INTO analysis(scan_id,worker_name,output) VALUES($1,$2,$3)", intID, res.WorkerName, res.Result)
					} else {
						log.Println("Worker ", res.WorkerName, " return with error(s) : ", res.Errors)
					}
				}
			}

		}(d)
	}

	select {}
}
