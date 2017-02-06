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
	workerName = "ciscoUmbrellaRank"
	workerDesc = "Evaluate the ranking of a site using the domains in the certificate and the Cisco Umbrella TOP 1m list"
	log        = logger.GetLogger()
)

type cutoprunner struct {
	Ranks map[string]int64
}

type Rank struct {
	Domain string `json:"domain"`
	Rank   int64  `json:"rank"`
}

func init() {
	runner := new(cutoprunner)
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

func (w cutoprunner) Run(in worker.Input, res chan worker.Result) {
	rank := Rank{
		Domain: strings.Trim(in.Certificate.Subject.CommonName, "*."),
		Rank:   certificate.Default_Cisco_Umbrella_Rank,
	}
	if val, ok := w.Ranks[strings.Trim(in.Certificate.Subject.CommonName, "*.")]; ok {
		rank.Rank = val
	}
	for _, san := range in.Certificate.X509v3Extensions.SubjectAlternativeName {
		if val, ok := w.Ranks[strings.Trim(san, "*.")]; ok {
			if val < rank.Rank {
				rank.Domain = strings.Trim(san, "*.")
				rank.Rank = val
			}
		}
	}
	err := in.DBHandle.UpdateCertificateRank(in.Certificate.ID, rank.Rank)
	if err != nil {
		res <- worker.Result{
			Success:    false,
			WorkerName: workerName,
			Errors:     []string{fmt.Sprintf("failed to update certificate rank: %v", err)},
			Result:     nil,
		}
	}
	out, err := json.Marshal(rank)
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
