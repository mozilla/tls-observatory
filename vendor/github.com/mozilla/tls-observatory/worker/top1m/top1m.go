package top1m

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
	workerDesc = "Rank a target and its certificate against the top 1 million websites published by Cisco Umbrella and Alexa"
	log        = logger.GetLogger()
)

type ranker struct {
	Ranks      map[string]int64
	AlexaRanks map[string]int64
}

// Analysis is the structure that stores ranks for a given run
type Analysis struct {
	Target      targetRank      `json:"target"`
	Certificate certificateRank `json:"certificate"`
}

type targetRank struct {
	Rank      rank   `json:"rank"`
	Domain    string `json:"domain"`
	CiscoRank rank   `json:"cisco_rank"`
	AlexaRank rank   `json:"alexa_rank"`
}

type rank int64

func (r rank) String() string {
	if r == certificate.Default_Cisco_Umbrella_Rank {
		return "unlisted"
	}
	return fmt.Sprintf("%d", r)
}

type certificateRank struct {
	Rank        rank   `json:"rank"`
	Domain      string `json:"domain"`
	CiscoRank   rank   `json:"cisco_rank"`
	CiscoDomain string `json:"cisco_domain"`
	AlexaRank   rank   `json:"alexa_rank"`
	AlexaDomain string `json:"alexa_domain"`
}

func init() {
	runner := new(ranker)
	worker.RegisterPrinter(workerName, worker.Info{Runner: runner, Description: workerDesc})

	runner.Ranks = make(map[string]int64)
	ciscoTop1mPath := "/etc/tls-observatory/cisco-top-1m.csv"
	if path := os.Getenv("TLSOBS_TOP1MPATH"); path != "" {
		ciscoTop1mPath = path
	}
	fd, err := os.Open(ciscoTop1mPath)
	defer fd.Close()
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

	runner.AlexaRanks = make(map[string]int64)
	alexaTop1mPath := "/etc/tls-observatory/alexa-top-1m.csv"
	if path := os.Getenv("TLSOBS_ALEXATOP1MPATH"); path != "" {
		alexaTop1mPath = path
	}
	afd, err := os.Open(alexaTop1mPath)
	defer afd.Close()
	if err != nil {
		log.Printf("Failed to initialize %s: %v", workerName, err)
		return
	}
	ar := csv.NewReader(afd)
	for {
		comp, err := ar.Read()
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
		if _, ok := runner.AlexaRanks[comp[1]]; !ok {
			runner.AlexaRanks[comp[1]] = rank
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
func (w ranker) analyseTargetRank(in worker.Input) (tr targetRank, err error) {
	tr = targetRank{
		Domain:    in.Target,
		Rank:      certificate.Default_Cisco_Umbrella_Rank,
		CiscoRank: certificate.Default_Cisco_Umbrella_Rank,
		AlexaRank: certificate.Default_Cisco_Umbrella_Rank,
	}
	if val, ok := w.Ranks[tr.Domain]; ok {
		tr.CiscoRank = rank(val)
		tr.Rank = rank(val)
	}
	if val, ok := w.AlexaRanks[tr.Domain]; ok {
		tr.AlexaRank = rank(val)
	}
	if tr.AlexaRank < tr.Rank {
		tr.Rank = tr.AlexaRank
	}
	return
}

// Find the highest rank of all the domains the certificate is valid for, and also
// store it in database alonside the certificate. This store three rank: one for cisco,
// one for alexa, and one that is the lowest rank for either.
func (w ranker) analyseCertificateRank(in worker.Input) (certRank certificateRank, err error) {
	// initialize the rank to a default value
	trimmedCert := strings.Trim(in.Certificate.Subject.CommonName, "*.")
	certRank = certificateRank{
		Domain:      trimmedCert,
		CiscoDomain: trimmedCert,
		AlexaDomain: trimmedCert,
		Rank:        certificate.Default_Cisco_Umbrella_Rank,
		CiscoRank:   certificate.Default_Cisco_Umbrella_Rank,
		AlexaRank:   certificate.Default_Cisco_Umbrella_Rank,
	}
	// find the rank of the common name of the certificate
	if val, ok := w.Ranks[strings.Trim(in.Certificate.Subject.CommonName, "*.")]; ok {
		certRank.CiscoRank = rank(val)
		certRank.Rank = rank(val)
	}
	// find the rank of the common name of the certificate
	if val, ok := w.AlexaRanks[strings.Trim(in.Certificate.Subject.CommonName, "*.")]; ok {
		certRank.AlexaRank = rank(val)
	}
	// find the highest rank of the certificate SAN and use it if higher than CN
	for _, san := range in.Certificate.X509v3Extensions.SubjectAlternativeName {
		if val, ok := w.Ranks[strings.Trim(san, "*.")]; ok {
			if rank(val) < certRank.Rank {
				certRank.CiscoDomain = strings.Trim(san, "*.")
				certRank.CiscoRank = rank(val)
			}
		}
		if val, ok := w.AlexaRanks[strings.Trim(san, "*.")]; ok {
			if rank(val) < certRank.AlexaRank {
				certRank.AlexaDomain = strings.Trim(san, "*.")
				certRank.AlexaRank = rank(val)
			}
		}
	}
	if certRank.CiscoRank < certRank.Rank {
		certRank.Rank = certRank.CiscoRank
		certRank.Domain = certRank.CiscoDomain
	}
	if certRank.AlexaRank < certRank.Rank {
		certRank.Rank = certRank.AlexaRank
		certRank.Domain = certRank.AlexaDomain
	}
	err = in.DBHandle.UpdateCertificateRank(in.Certificate.ID, int64(certRank.Rank))
	return
}

func (w ranker) AnalysisPrinter(r []byte, printAll interface{}) (results []string, err error) {
	var a Analysis
	err = json.Unmarshal(r, &a)
	if err != nil {
		err = fmt.Errorf("Top 1M: failed to parse results: %v", err)
		return
	}
	results = append(results, "* Top 1M:")
	results = append(results, fmt.Sprintf("  - target %q is ranked %s (cisco rank is %s, alexa ranks is %s)",
		a.Target.Domain, a.Target.Rank.String(), a.Target.CiscoRank.String(), a.Target.AlexaRank.String()))

	results = append(results, fmt.Sprintf("  - certificate valid for %q is ranked %s (cisco ranks %q as %s, alexa ranks %q as %s)",
		a.Certificate.Domain, a.Certificate.Rank.String(), a.Certificate.CiscoDomain, a.Certificate.CiscoRank.String(), a.Certificate.AlexaDomain, a.Certificate.AlexaRank.String()))
	return
}
