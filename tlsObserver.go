package main

import (
	"flag"
	"os"
	"runtime"
	"strconv"
	"time"

	"github.com/Sirupsen/logrus"

	"github.com/mozilla/TLS-Observer/certificate"
	"github.com/mozilla/TLS-Observer/config"
	"github.com/mozilla/TLS-Observer/connection"
	"github.com/mozilla/TLS-Observer/logger"
	"github.com/mozilla/TLS-Observer/modules/amqpmodule"
	pg "github.com/mozilla/TLS-Observer/modules/postgresmodule"
	"github.com/mozilla/TLS-Observer/worker"
)

const rxQueue = "cert_rx_queue"
const rxRoutKey = "scan_ready"

var broker *amqpmodule.Broker
var db *pg.DB
var log = logger.GetLogger()

func main() {

	conf := config.ObserverConfig{}

	var cfgFile, cipherscan string
	flag.StringVar(&cfgFile, "c", "/etc/observer/observer.cfg", "Input file csv format")
	flag.StringVar(&cipherscan, "b", "/etc/observer/cipherscan/cipherscan", "Cipherscan binary location")
	flag.Parse()

	logger.SetLevelToWarning()

	_, err := os.Stat(cfgFile)
	log.Fatal("Missing configuration file from '-c' or /etc/observer/observer.cfg")

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

	log.WithFields(logrus.Fields{
		"error": err.Error(),
	}).Fatal("Failed to connect to database")

	broker, err = amqpmodule.RegisterURL(conf.General.RabbitMQRelay)

	log.WithFields(logrus.Fields{
		"error": err.Error(),
	}).Fatal("Failed to register RabbitMQ")

	msgs, err := broker.Consume(rxQueue, rxRoutKey)

	certificate.Setup(conf, db)

	for d := range msgs {

		log.WithFields(logrus.Fields{
			"scan_id": string(d),
		}).Debug("Received new scan ")

		go func(id []byte) {

			tx, err := db.Begin()

			if err != nil {
				log.Println(err)
				return
			}

			intID, err := strconv.ParseInt(string(id), 10, 64)

			scan, err := db.GetScan(intID)

			if err != nil {

				log.WithFields(logrus.Fields{
					"scan_id": string(d),
					"error":   err.Error(),
				}).Error("Could not find/decode scan")
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
						log.WithFields(logrus.Fields{
							"scan_id":     string(d),
							"scan_Target": scan.Target,
							"error":       err.Error(),
						}).Error("Could not get certificate info")
						tx.Rollback()
					}

				}

				log.WithFields(logrus.Fields{
					"scan_id":  string(d),
					"cert_id":  certID,
					"trust_id": trustID,
				}).Debug("Retrieved certs")

				_, err = db.Exec("UPDATE scans SET cert_id=$1,trust_id=$2,has_tls=TRUE WHERE id=$3", certID, trustID, intID)

				if err != nil {
					log.WithFields(logrus.Fields{
						"scan_id": string(d),
						"cert_id": certID,
						"error":   err.Error(),
					}).Error("Could not update scans for cert")
				}

				err = db.UpdateScanCompletionPercentage(intID, 20)
				if err != nil {
					log.WithFields(logrus.Fields{
						"scan_id": string(d),
						"error":   err.Error(),
					}).Error("Could not update completion percentage for scan")
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

						log.WithFields(logrus.Fields{
							"scan_id": string(d),
							"error":   err.Error(),
						}).Error("Could not get TLS connection info")
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

					log.WithFields(logrus.Fields{
						"scan_id": string(d),
					}).Debug("Scanners timed out")
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
						log.WithFields(logrus.Fields{
							"scan_id": string(d),
							"error":   err.Error(),
						}).Error("Could not update completion percentage")
					}

					if res.Success {
						tx.Exec("INSERT INTO analysis(scan_id,worker_name,output) VALUES($1,$2,$3)", intID, res.WorkerName, res.Result)
					} else {
						log.WithFields(logrus.Fields{
							"worker_name": res.WorkerName,
							"errors":      res.Errors,
						}).Error("Worker returned with errors")
					}
				}
			}

		}(d)
	}

	select {}
}
