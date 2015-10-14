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

	certificate.Setup(conf)

	for d := range msgs {

		go func(id []byte) {

			tx, err := db.Begin()

			if err != nil {
				log.Println(err)
				return
			}

			scan, err := getScan(string(id))

			if err != nil {
				log.Println(err, "Could not find /decode scan with id: ", string(id))
				tx.Rollback()
				return
			}

			totalWorkers := len(worker.AvailableWorkers)

			resChan := make(chan worker.WorkerResult)
			defer close(resChan)

			go func() {
				certID, jsonCert, err := certificate.HandleCert(scan.target)
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

			endedWorkers := 0
			select {
			case <-timeout:
				err := tx.Commit()
				return
				//wait no more than 10 secs for all workers to finish.

			case <-resChan:
				endedWorkers += endedWorkers
				currCompletionPercentage := ((endedWorkers/totalWorkers)*80 + 20) / 100
				//write worker result to db
				//update completion percentage in db
			}

		}(d)
	}

	select {}
}

func getScan(id string) (Scan, error) {

	s := Scan{}
	s.id = id

	row := db.QueryRow(`SELECT time_stamp, target, replay, has_tls, 	cert_id,
	is_valid, completion_perc, validation_error, is_ubuntu_valid, is_mozilla_valid,
	is_windows_valid, is_apple_valid, conn_info
	FROM certificates WHERE id=$1`, id)

	cert := &certificate.Certificate{}

	err := row.Scan(&s.time_stamp, &s.target, &s.replay, &s.has_tls, &s.cert_id,
		&s.is_valid, &s.validation_error, &s.is_ubuntu_valid, &s.is_mozilla_valid,
		&s.is_windows_valid, &s.is_apple_valid, &s.conn_info)

	if err != nil {
		return s, err
	}

	return s, nil

}
