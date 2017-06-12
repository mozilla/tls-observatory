package sslLabsClientSupport

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/mozilla/tls-observatory/certificate"
	"github.com/mozilla/tls-observatory/logger"
	"github.com/mozilla/tls-observatory/worker"
)

var (
	workerName = "top1m"
	workerDesc = "Rank a target and its certificate against the top 1 million websites published by Cisco Umbrella"
	log        = logger.GetLogger()
)

type ranker struct {
	Ranks map[string]int64
}

// Analysis is the structure that stores ranks for a given run
type Analysis struct {
	Target      targetRank      `json:"target"`
	Certificate certificateRank `json:"certificate"`
}

type targetRank struct {
	Rank   int64  `json:"rank"`
	Domain string `json:"domain"`
}

type certificateRank struct {
	Rank   int64  `json:"rank"`
	Domain string `json:"domain"`
}

func init() {
	runner := new(ranker)
	runner.Ranks = make(map[string]int64)
	fd, err := os.Open("/etc/tls-observatory/top-1m.csv")
	if err != nil {
		log.Printf("Failed to initialize %s: %v", workerName, err)
		return
	}
	r := csv.NewReader(fd)
	for {
		comp, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Printf("%s - failed to read csv data: %v", workerName, err)
			return
		}
		if len(comp) != 2 {
			log.Printf("%s - invalid entry format: %s", workerName, comp)
			return
		}
		rank, err := strconv.ParseInt(comp[0], 10, 64)
		if err != nil {
			log.Printf("%s - invalid rank integer: %v", workerName, err)
			return
		}
		if _, ok := runner.Ranks[comp[1]]; !ok {
			runner.Ranks[comp[1]] = rank
		}
	}
	worker.RegisterWorker(workerName, worker.Info{Runner: runner, Description: workerDesc})
}

func (w ranker) Run(in worker.Input, res chan worker.Result) {
	var (
		a   Analysis
		err error
	)
	a.Target, err = w.analyseTargetRank(in)
	if err != nil {
		res <- worker.Result{
			Success:    false,
			WorkerName: workerName,
			Errors:     []string{fmt.Sprintf("failed to analyse target rank: %v", err)},
			Result:     nil,
		}
	}
	a.Certificate, err = w.analyseCertificateRank(in)
	if err != nil {
		res <- worker.Result{
			Success:    false,
			WorkerName: workerName,
			Errors:     []string{fmt.Sprintf("failed to analyse certificate rank: %v", err)},
			Result:     nil,
		}
	}
	out, err := json.Marshal(a)
	if err != nil {
		res <- worker.Result{
			Success:    false,
			WorkerName: workerName,
			Errors:     []string{fmt.Sprintf("failed to marshal results: %v", err)},
			Result:     nil,
		}
	} else {
		res <- worker.Result{
			Success:    true,
			WorkerName: workerName,
			Errors:     nil,
			Result:     out,
		}
	}
}

// Find the rank of the target
func (w ranker) analyseTargetRank(in worker.Input) (targetRank targetRank, err error) {
	targetRank.Domain = in.Target
	targetRank.Rank = certificate.Default_Cisco_Umbrella_Rank
	if val, ok := w.Ranks[targetRank.Domain]; ok {
		targetRank.Rank = val
	}
	return
}

// Find the highest rank of all the domains the certificate is valid for, and also
// store it in database alonside the certificate
func (w ranker) analyseCertificateRank(in worker.Input) (certRank certificateRank, err error) {
	// initialize the rank to a default value
	certRank.Domain = strings.Trim(in.Certificate.Subject.CommonName, "*.")
	certRank.Rank = certificate.Default_Cisco_Umbrella_Rank
	// find the rank of the common name of the certificate
	if val, ok := w.Ranks[strings.Trim(in.Certificate.Subject.CommonName, "*.")]; ok {
		certRank.Rank = val
	}
	// find the highest rank of the certificate SAN and use it if higher than CN
	for _, san := range in.Certificate.X509v3Extensions.SubjectAlternativeName {
		if val, ok := w.Ranks[strings.Trim(san, "*.")]; ok {
			if val < certRank.Rank {
				certRank.Domain = strings.Trim(san, "*.")
				certRank.Rank = val
			}
		}
	}
	err = in.DBHandle.UpdateCertificateRank(in.Certificate.ID, certRank.Rank)
	return
}
