package main

import (
	"flag"
	"os"
	"runtime"
	//"strconv"
	"time"

	"github.com/Sirupsen/logrus"

	"github.com/mozilla/tls-observatory/certificate"
	"github.com/mozilla/tls-observatory/config"
	"github.com/mozilla/tls-observatory/connection"
	pg "github.com/mozilla/tls-observatory/database"
	"github.com/mozilla/tls-observatory/logger"
	"github.com/mozilla/tls-observatory/worker"
)

var db *pg.DB
var log = logger.GetLogger()

func main() {
	var (
		cfgFile, cipherscan string
		debug               bool
	)
	flag.StringVar(&cfgFile, "c", "/etc/tls-observatory/scanner.cfg", "Input file csv format")
	flag.StringVar(&cipherscan, "b", "/opt/cipherscan/cipherscan", "Cipherscan binary location")
	flag.BoolVar(&debug, "debug", false, "Set debug logging")
	flag.Parse()

	if debug {
		logger.SetLevelToDebug()
	}

	conf, err := config.Load(cfgFile)
	if err != nil {
		log.Fatal("Failed to load configuration: %v", err)
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

	cores := runtime.NumCPU()
	runtime.GOMAXPROCS(cores * conf.General.GoRoutines)

	db, err = pg.RegisterConnection(conf.General.PostgresDB, conf.General.PostgresUser, conf.General.PostgresPass, conf.General.Postgres, "disable")
	if err != nil {
		log.WithFields(logrus.Fields{
			"error": err.Error(),
		}).Fatal("Failed to connect to database")
	}

	incomingScans := db.RegisterScanListener(conf.General.PostgresDB, conf.General.PostgresUser, conf.General.PostgresPass, conf.General.Postgres, "disable")
	certificate.Setup(conf, db)

	for scanId := range incomingScans {
		go scan(scanId, cipherscan)
	}
}

func scan(scanId int64, cipherscan string) {

	log.WithFields(logrus.Fields{
		"scan_id": scanId,
	}).Debug("Received new scan ")

	scan, err := db.GetScanByID(scanId)
	if err != nil {
		log.WithFields(logrus.Fields{
			"scan_id": scanId,
			"error":   err.Error(),
		}).Error("Could not find/decode scan")
		return
	}
	var completion int = 0

	// Retrieve the certificate from the target
	certID, trustID, err := certificate.HandleCert(scan.Target)
	if err != nil {
		err, ok := err.(certificate.NoTLSCertsErr)
		if ok {
			//nil cert, does not implement TLS
			db.Exec("UPDATE scans SET has_tls=FALSE WHERE id=$1", scanId)
			return
		} else {
			log.WithFields(logrus.Fields{
				"scan_id":     scanId,
				"scan_Target": scan.Target,
				"error":       err.Error(),
			}).Error("Could not get certificate info")
		}
	}
	log.WithFields(logrus.Fields{
		"scan_id":  scanId,
		"cert_id":  certID,
		"trust_id": trustID,
	}).Debug("Retrieved certs")

	isTrustValid, err := certificate.IsTrustValid(trustID)

	if err != nil {
		log.WithFields(logrus.Fields{
			"scan_id": scanId,
			"cert_id": certID,
			"error":   err.Error(),
		}).Error("Could not get if trust is valid")
		return
	}

	_, err = db.Exec("UPDATE scans SET cert_id=$1,trust_id=$2,has_tls=TRUE,is_valid=$3 WHERE id=$4", certID, trustID, isTrustValid, scanId)
	if err != nil {
		log.WithFields(logrus.Fields{
			"scan_id": scanId,
			"cert_id": certID,
			"error":   err.Error(),
		}).Error("Could not update scans for cert")
	}
	completion += 20
	err = db.UpdateScanCompletionPercentage(scanId, completion)
	if err != nil {
		log.WithFields(logrus.Fields{
			"scan_id": scanId,
			"error":   err.Error(),
		}).Error("Could not update completion percentage for scan")
	}

	// Cipherscan the target
	js, err := connection.Connect(scan.Target, cipherscan)
	if err != nil {
		err, ok := err.(connection.NoTLSConnErr)
		if ok {
			//does not implement TLS
			db.Exec("UPDATE scans SET has_tls=FALSE WHERE id=$1", scanId)
			return
		} else {
			log.WithFields(logrus.Fields{
				"scan_id": scanId,
				"error":   err.Error(),
			}).Error("Could not get TLS connection info")
		}
	} else {
		db.Exec("UPDATE scans SET conn_info=$1 WHERE id=$2", js, scanId)
		completion += 20
		err = db.UpdateScanCompletionPercentage(scanId, completion)
		if err != nil {
			log.WithFields(logrus.Fields{
				"scan_id": scanId,
				"error":   err.Error(),
			}).Error("Could not update completion percentage for scan")
		}
	}

	// launch workers that evaluate the results
	resChan := make(chan worker.WorkerResult)
	for _, wrkInfo := range worker.AvailableWorkers {
		go wrkInfo.Runner.(worker.Worker).Run([]byte(scan.Target), resChan)
	}

	totalWorkers := len(worker.AvailableWorkers)

	log.WithFields(logrus.Fields{
		"scan_id": scanId,
		"workers": totalWorkers,
	}).Debug("Running workers")

	if totalWorkers > 0 {
		endedWorkers := 0
		select {
		case <-time.After(10 * time.Second):

			log.WithFields(logrus.Fields{
				"scan_id": scanId,
			}).Debug("Scanners timed out")

			if err != nil {
				log.Println(err)
			}
			return

		case res := <-resChan:
			endedWorkers += endedWorkers
			currCompletionPercentage := ((endedWorkers/totalWorkers)*60 + 40)

			log.WithFields(logrus.Fields{
				"scan_id":        scanId,
				"worker_name":    res.WorkerName,
				"result_success": res.Success,
				"result_data":    string(res.Result),
			}).Debug("Received results from worker")

			err = db.UpdateScanCompletionPercentage(scanId, currCompletionPercentage)
			if err != nil {
				log.WithFields(logrus.Fields{
					"scan_id": scanId,
					"error":   err.Error(),
				}).Error("Could not update completion percentage")
			}

			if res.Success {
				db.Exec("INSERT INTO analysis(scan_id,worker_name,output) VALUES($1,$2,$3)", scanId, res.WorkerName, res.Result)
			} else {
				log.WithFields(logrus.Fields{
					"worker_name": res.WorkerName,
					"errors":      res.Errors,
				}).Error("Worker returned with errors")
			}
		}
	}
}
