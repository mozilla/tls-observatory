package caaWorker

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/miekg/dns"
	"github.com/mozilla/tls-observatory/worker"
)

var (
	workerName = "caaWorker"
	workerDesc = "Checks domains DNS records for a CAA record and reports it."
)

func init() {
	worker.RegisterWorker(workerName, worker.Info{Runner: new(eval), Description: workerDesc})
}

// Result describes the result produced by CAAWorker
type Result struct {
	HasCAA       bool     `json:"has_caa"`
	Host         string   `json:"host"`
	IssueCAs     []string `json:"issue"`
	IssueWildCAs []string `json:"issuewild"`
}

type eval struct{}

// Run implements the worker interface.It is called to get the worker results.
func (e eval) Run(in worker.Input, resChan chan worker.Result) {
	result := worker.Result{WorkerName: workerName, Success: true}
	caaRes := Result{}

	hostPieces := strings.Split(in.Target, ".")
	for i := 0; i < len(hostPieces); i++ {
		host := strings.Join(hostPieces[i:], ".")

		msg := new(dns.Msg)
		msg.SetQuestion(dns.Fqdn(host), dns.TypeCAA)

		client := dns.Client{}
		res, _, err := client.Exchange(msg, "8.8.8.8:53")
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("CAA lookup failed for %s: %v", host, err))
			continue
		}

		if res.Rcode != dns.RcodeSuccess {
			result.Errors = append(result.Errors, fmt.Sprintf("CAA lookup failed for %s with %s", host, dns.RcodeToString[res.Rcode]))
			continue
		}

		for _, rr := range res.Answer {
			if caa, ok := rr.(*dns.CAA); ok {
				caaRes.HasCAA = true
				if caa.Tag == "issue" {
					caaRes.IssueCAs = append(caaRes.IssueCAs, caa.Value)
				} else if caa.Tag == "issuewild" {
					caaRes.IssueWildCAs = append(caaRes.IssueWildCAs, caa.Value)
				}
			}
		}

		if caaRes.HasCAA {
			caaRes.Host = host
			break
		}
	}

	res, err := json.Marshal(caaRes)
	if err != nil {
		result.Errors = append(result.Errors, err.Error())
		result.Success = false
	} else {
		result.Success = true
		result.Result = res
	}

	resChan <- result
}
