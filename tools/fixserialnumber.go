package main

import (
	"crypto/x509"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"math"
	"os"

	"github.com/mozilla/tls-observatory/certificate"
	"github.com/mozilla/tls-observatory/database"
)

type job struct {
	id int64
	// Needs to be *string because apparently serial numbers can be NULL in the db
	currentSerialNumber *string
	cert                *x509.Certificate
}

type result struct {
	id      int64
	changed bool
	err     error
}

func main() {
	var workerCount int
	var batchSize int64
	var minID int64
	var maxID int64
	flag.IntVar(&workerCount, "workers", 4, "Number of workers to use")
	flag.Int64Var(&batchSize, "batchSize", 1000, "Batch size")
	flag.Int64Var(&minID, "minID", 0, "Minimum certificate ID to modify")
	flag.Int64Var(&maxID, "maxID", math.MaxInt64, "Maximum certificate ID to modify")
	flag.Parse()
	jobs := make(chan job, batchSize)
	results := make(chan result, batchSize)

	db, err := database.RegisterConnection(
		os.Getenv("TLSOBS_POSTGRESDB"),
		os.Getenv("TLSOBS_POSTGRESUSER"),
		os.Getenv("TLSOBS_POSTGRESPASS"),
		os.Getenv("TLSOBS_POSTGRES"),
		"require",
	)
	if err != nil {
		log.Fatalf("Error connecting to database: %s", err)
	}
	defer db.Close()

	for w := 1; w <= workerCount; w++ {
		go worker(w, jobs, results, db)
	}
	changedCount := 0
	errorCount := 0
	total := 0
	go func() {
		for {
			log.Printf("Fetching %d certificates with id > %d", batchSize, minID)
			nextBatch, err := fetchNextBatchWithRetries(5, db, minID, batchSize)
			if err != nil {
				log.Fatalf("Error fetching next batch: %s", err)
			}
			if len(nextBatch) == 0 || minID >= maxID {
				close(jobs)
				close(results)
				log.Printf("Done. %d/%d errors. %d/%d changed.", errorCount, total, changedCount, total)
				return
			}
			total += len(nextBatch)
			for _, j := range nextBatch {
				jobs <- j
				minID = j.id
			}
		}
	}()
	for result := range results {
		if result.err != nil {
			errorCount++
			log.Printf("Received error for cert id %d: %s", result.id, result.err)
		}
		if result.changed {
			changedCount++
		}
	}
}

func fetchNextBatchWithRetries(retries int, db *database.DB, minID int64, batchSize int64) (jobs []job, err error) {
	for i := 0; i < retries; i++ {
		jobs, err = fetchNextBatch(db, minID, batchSize)
		if err == nil {
			break
		}
	}
	return
}

func fetchNextBatch(db *database.DB, minID int64, batchSize int64) ([]job, error) {
	rows, err := db.Query(`SELECT id, serial_number, raw_cert
							   FROM certificates
							   WHERE id > $1
							   ORDER BY id
							   LIMIT $2`,
		minID,
		batchSize,
	)
	if err != nil {
		log.Fatalf("Error querying database: %s", err)
	}
	defer rows.Close()
	var jobs []job
	for rows.Next() {
		var j job
		var b64Crt string
		if err = rows.Scan(&j.id, &j.currentSerialNumber, &b64Crt); err != nil {
			return nil, fmt.Errorf("Error scanning row: %s", err)
		}
		cert, err := b64RawCertToX509Cert(b64Crt)
		if err != nil {
			log.Printf("Error converting database certificate to crypto/x509 certificate: %s", err)
			continue
		}
		j.cert = cert
		jobs = append(jobs, j)
	}
	return jobs, nil
}

func b64RawCertToX509Cert(b64Crt string) (*x509.Certificate, error) {
	rawCert, err := base64.StdEncoding.DecodeString(b64Crt)
	if err != nil {
		return nil, fmt.Errorf("Error b64 decoding certificate: %s", err)
	}
	cert, err := x509.ParseCertificate(rawCert)
	if err != nil {
		return nil, fmt.Errorf("Error parsing x509 certificate: %s", err)
	}
	return cert, nil
}

func worker(id int, jobs <-chan job, results chan result, db *database.DB) {
	for j := range jobs {
		correctSerialNumber, err := certificate.GetHexASN1Serial(j.cert)
		if err != nil {
			results <- result{id: j.id, err: err}
			continue
		}
		if correctSerialNumber == *j.currentSerialNumber {
			// Serial number is already stored correctly in the database
			results <- result{id: j.id, err: nil}
			continue
		}
		err = updateSerialNumberInDB(db, j.id, correctSerialNumber)
		if err != nil {
			results <- result{
				id:  j.id,
				err: fmt.Errorf("Error updating serial number in database: %s", err),
			}
			continue
		}
		results <- result{id: j.id, err: nil, changed: true}
	}
}

func updateSerialNumberInDB(db *database.DB, id int64, correctSerialNumber string) error {
	_, err := db.Exec(`UPDATE certificates
					SET serial_number = $1
					WHERE id = $2`, correctSerialNumber, id)
	return err
}
