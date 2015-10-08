package main

import (
	"time"

	"github.com/mozilla/TLS-Observer/certificate"
	"github.com/mozilla/TLS-Observer/config"
	"github.com/mozilla/TLS-Observer/connection"
	"github.com/mozilla/TLS-Observer/modules/amqpmodule"
)

//CREATE TABLE scans  (
//	id                         	serial primary key,
//	time_stamp	           		timestamp NOT NULL,
//  target						varchar NOT NULL,
//  replay 				        integer NULL, //hours or days
//	cert_id		              	varchar references certificates(id),
//	conn_id                  	varchar references connections(id),
//	worker_outputs              	integer[] NULL, // ids of the worker table references applying to this scan
//	score                    	varchar NULL,
//	old_compliant               bool NULL,
//	intermediate_compliant      bool NULL,
//
//);

//CREATE TABLE worker_output  (
//	id                         	serial primary key,
//	worker_name	           		varchar NOT NULL,
//  output						jsonb NULL
//);

func main() {
	var err error

	printIntro()

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

		go func(domain []byte) {

			resChan := make(chan modules.ModuleResult)

			//run certificate go routine
			go func() {
				certificate.HandleCert(domain)
			}()
			//run connection go routine
			go func() {
				connection.Connect(domain)
			}()

			go func() {
				for name, wrkInfo := range worker.AvailableWorkers {

					go wrkInfo.Runner.(modules.Moduler).Run(domain, resChan)
				}
			}()

			timeout := make(chan bool, 1)
			go func() {
				time.Sleep(10 * time.Second)
				timeout <- true
			}()

			select {
			case <-timeout:

			case <-resChan:

			}

		}(d.Body)
	}

	select {}
}
