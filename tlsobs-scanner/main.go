package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/mozilla/tls-observatory/config"
	"github.com/mozilla/tls-observatory/connection"
	pg "github.com/mozilla/tls-observatory/database"
	"github.com/mozilla/tls-observatory/logger"
	"github.com/mozilla/tls-observatory/metrics"
	"github.com/mozilla/tls-observatory/worker"
)

var db *pg.DB
var log = logger.GetLogger()

func main() {
	var (
		cfgFile, cipherscan string
		debug               bool
	)
	flag.StringVar(&cfgFile, "c", "/etc/tls-observatory/scanner.cfg", "Configuration file")
	flag.StringVar(&cipherscan, "b", "/opt/cipherscan/cipherscan", "Cipherscan binary location")
	flag.BoolVar(&debug, "debug", false, "Set debug logging")
	flag.Parse()

	if debug {
		logger.SetLevelToDebug()
	}

	conf, err := config.Load(cfgFile)
	if err != nil {
		log.Fatal(fmt.Sprintf("Failed to load configuration: %v", err))
	}
	if !conf.General.Enable && os.Getenv("TLSOBS_SCANNER_ENABLE") != "on" {
		log.Fatal("Scanner is disabled in configuration")
	}

	_, err = os.Stat(cipherscan)
	if err != nil {
		log.WithFields(logrus.Fields{
			"error": err.Error(),
		}).Error("Could not locate cipherscan executable. TLS connection capabilities will not be available.")
	}

	// increase the n
	runtime.GOMAXPROCS(conf.General.MaxProc)

	dbtls := "disable"
	if conf.General.PostgresUseTLS {
		dbtls = "verify-full"
	}
	db, err = pg.RegisterConnection(
		conf.General.PostgresDB,
		conf.General.PostgresUser,
		conf.General.PostgresPass,
		conf.General.Postgres,
		dbtls)
	defer db.Close()
	if err != nil {
		log.WithFields(logrus.Fields{
			"error": err.Error(),
		}).Fatal("Failed to connect to database")
	}
	db.SetMaxOpenConns(conf.General.MaxProc)
	db.SetMaxIdleConns(10)
	// simple DB watchdog, crashes the process if connection dies
	go func() {
		for {
			var one uint
			err = db.QueryRow("SELECT 1").Scan(&one)
			if err != nil {
				log.Fatal("Database connection failed:", err)
			}
			if one != 1 {
				log.Fatal("Apparently the database doesn't know the meaning of one anymore. Crashing.")
			}
			time.Sleep(10 * time.Second)
		}
	}()
	incomingScans := db.RegisterScanListener(
		conf.General.PostgresDB,
		conf.General.PostgresUser,
		conf.General.PostgresPass,
		conf.General.Postgres,
		dbtls)
	Setup(conf)

	activeScans := 0
	sender, _ := metrics.NewSender()
	scanner := scanner{sender}
	for {
		select {
		case scanID := <-incomingScans:
			// new scan, send it to the first available scanner
			for {
				if activeScans >= conf.General.MaxProc {
					time.Sleep(time.Second)
				} else {
					break
				}
			}
			go func() {
				activeScans++
				scanner.scan(scanID, cipherscan)
				activeScans--
			}()
		case <-time.After(conf.General.Timeout * time.Minute):
			log.Fatalf("No new scan received in %d minutes, shutting down", conf.General.Timeout)
		}
	}
}

type scanner struct {
	metricsSender *metrics.Sender
}

func (s scanner) scan(scanID int64, cipherscan string) {
	log.WithFields(logrus.Fields{
		"scan_id": scanID,
	}).Info("Received new scan")
	db.Exec("UPDATE scans SET attempts = attempts + 1 WHERE id=$1", scanID)

	scan, err := db.GetScanByID(scanID)
	if err != nil {
		log.WithFields(logrus.Fields{
			"scan_id": scanID,
			"error":   err.Error(),
		}).Error("Could not find/decode scan")
		return
	}

	// Send a completed scan event to CloudWatch when the function returns
	defer func() {
		if s.metricsSender != nil {
			s.metricsSender.CompletedScan()
		}
	}()

	var completion int

	// Retrieve the certificate from the target
	certID, trustID, chain, err := handleCert(scan.Target)
	if err != nil {
		db.Exec("UPDATE scans SET has_tls=FALSE, completion_perc=100 WHERE id=$1", scanID)
		log.WithFields(logrus.Fields{
			"scan_id":     scanID,
			"scan_target": scan.Target,
			"error":       err.Error(),
		}).Error("Could not get certificate info")
		return
	}
	log.WithFields(logrus.Fields{
		"scan_id":  scanID,
		"cert_id":  certID,
		"trust_id": trustID,
	}).Debug("Certificate retrieved from target")

	completion += 20
	_, err = db.Exec(`UPDATE scans SET cert_id=$1, has_tls=TRUE, completion_perc=$2
			WHERE id=$3`, certID, completion, scanID)
	if err != nil {
		db.Exec("UPDATE scans SET has_tls=FALSE, completion_perc=100 WHERE id=$1", scanID)
		log.WithFields(logrus.Fields{
			"scan_id": scanID,
			"cert_id": certID,
			"error":   err.Error(),
		}).Error("Could not update scans for cert")
		return
	}

	completion += 30
	if trustID > 0 {
		isTrustValid, err := db.IsTrustValid(trustID)
		if err != nil {
			db.Exec("UPDATE scans SET has_tls=FALSE, completion_perc=100 WHERE id=$1", scanID)
			log.WithFields(logrus.Fields{
				"scan_id":  scanID,
				"cert_id":  certID,
				"trust_id": trustID,
				"error":    err.Error(),
			}).Error("Failed to determine certificate trust")
			return
		}
		_, err = db.Exec(`UPDATE scans SET trust_id=$1, is_valid=$2, completion_perc=$3
			WHERE id=$4`, trustID, isTrustValid, completion, scanID)
		if err != nil {
			db.Exec("UPDATE scans SET has_tls=FALSE, completion_perc=100 WHERE id=$1", scanID)
			log.WithFields(logrus.Fields{
				"scan_id": scanID,
				"cert_id": certID,
				"error":   err.Error(),
			}).Error("Could not update scans for cert")
			return
		}
	}

	// Cipherscan the target
	js, err := connection.Connect(scan.Target, cipherscan)
	if err != nil {
		_, ok := err.(connection.NoTLSConnErr)
		if ok {
			//does not implement TLS
			db.Exec("UPDATE scans SET has_tls=FALSE, completion_perc=100 WHERE id=$1", scanID)
		} else {
			//appears to implement TLS but cipherscan failed so store an error
			db.Exec("UPDATE scans SET scan_error=$1, completion_perc=100 WHERE id=$2", err.Error(), scanID)
			log.WithFields(logrus.Fields{
				"scan_id": scanID,
				"error":   err.Error(),
			}).Error("Could not get TLS connection info")
		}
		return
	}
	completion += 20
	_, err = db.Exec("UPDATE scans SET conn_info=$1, completion_perc=$2 WHERE id=$3",
		js, completion, scanID)
	if err != nil {
		log.WithFields(logrus.Fields{
			"scan_id": scanID,
			"error":   err.Error(),
		}).Error("Could not update connection information for scan")
	}

	// Prepare worker input
	cert, err := db.GetCertByID(certID)
	if err != nil {
		log.WithFields(logrus.Fields{
			"scan_id": scanID,
			"cert_id": certID,
			"err":     err,
		}).Error("Could not get certificate from db to pass to workers")
		return
	}
	var conn_info connection.Stored
	err = json.Unmarshal(js, &conn_info)
	if err != nil {
		log.WithFields(logrus.Fields{
			"scan_id": scanID,
		}).Error("Could not parse connection info to pass to workers")
		return
	}
	workerInput := worker.Input{
		DBHandle:         db,
		Scanid:           scanID,
		Target:           scan.Target,
		Certificate:      *cert,
		CertificateChain: chain,
		Connection:       conn_info,
	}
	// launch workers that evaluate the results
	resChan := make(chan worker.Result)
	totalWorkers := 0
	for k, wrkInfo := range worker.AvailableWorkers {
		workerInput.Params, _ = scan.AnalysisParams[k]
		go wrkInfo.Runner.(worker.Worker).Run(workerInput, resChan)
		totalWorkers++
	}
	log.WithFields(logrus.Fields{
		"scan_id": scanID,
		"count":   totalWorkers,
	}).Info("Running workers")

	// read the results from the results chan in a loop until all workers have ran or expired
	for endedWorkers := 0; endedWorkers < totalWorkers; endedWorkers++ {
		select {
		case <-time.After(30 * time.Second):
			log.WithFields(logrus.Fields{
				"scan_id": scanID,
			}).Error("Analysis workers timed out after 30 seconds")
			goto updatecompletion
		case res := <-resChan:
			completion = ((endedWorkers/totalWorkers)*60 + completion)
			log.WithFields(logrus.Fields{
				"scan_id":     scanID,
				"worker_name": res.WorkerName,
				"success":     res.Success,
				"result":      string(res.Result),
			}).Debug("Received results from worker")

			err = db.UpdateScanCompletionPercentage(scanID, completion)
			if err != nil {
				log.WithFields(logrus.Fields{
					"scan_id": scanID,
					"error":   err.Error(),
				}).Error("Could not update completion percentage")
				continue
			}
			if !res.Success {
				log.WithFields(logrus.Fields{
					"worker_name": res.WorkerName,
					"errors":      res.Errors,
				}).Error("Worker returned with errors")
			} else {
				_, err = db.Exec("INSERT INTO analysis(scan_id,worker_name,output,success) VALUES($1,$2,$3,$4)",
					scanID, res.WorkerName, res.Result, res.Success)
				if err != nil {
					log.WithFields(logrus.Fields{
						"scan_id": scanID,
						"error":   err.Error(),
					}).Error("Could not insert worker results in database")
					continue
				}
				if s.metricsSender != nil {
					s.metricsSender.NewAnalysis()
				}
				log.WithFields(logrus.Fields{
					"scan_id":     scanID,
					"worker_name": res.WorkerName,
				}).Info("Results from worker stored in database")
			}
		}
	}
updatecompletion:
	err = db.UpdateScanCompletionPercentage(scanID, 100)
	if err != nil {
		log.WithFields(logrus.Fields{
			"scan_id": scanID,
			"error":   err.Error(),
		}).Error("Could not update completion percentage")
	}
	return
}
