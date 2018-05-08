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

//Use the google DNS servers as fallback
var DNSServer = "8.8.8.8:53"

func init() {
	runner := new(eval)
	worker.RegisterPrinter(workerName, worker.Info{Runner: runner, Description: workerDesc})
	cfg, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err == nil && len(cfg.Servers) > 0 {
		//if there are configured nameservers use them
		DNSServer = strings.Join([]string{cfg.Servers[0], cfg.Port}, ":")
	}
	worker.RegisterWorker(workerName, worker.Info{Runner: runner, Description: workerDesc})
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
		res, _, err := client.Exchange(msg, DNSServer)
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

// Assertor compares 2 caaResults and reports differences.
func (e eval) Assertor(caaResult, assertresults []byte) (pass bool, body []byte, err error) {
	var result, assertres Result
	pass = false
	err = json.Unmarshal(caaResult, &result)
	if err != nil {
		return
	}
	err = json.Unmarshal(assertresults, &assertres)
	if err != nil {
		return
	}

	if result.HasCAA != assertres.HasCAA {
		body = []byte("CAA mismatch")
		return
	}
	if result.Host != assertres.Host {
		body = []byte(fmt.Sprintf(`Assertion failed MatchedHost= %s`,
			result.Host))
		return
	}

	if len(result.IssueCAs) != len(assertres.IssueCAs) {
		body = []byte("Issue CAs count mismatch")
		return
	}

	for i := range result.IssueCAs {
		if result.IssueCAs[i] != assertres.IssueCAs[i] {
			body = []byte(fmt.Sprintf(`Issue CAs mismatch %s != %s`,
				result.IssueCAs[i], assertres.IssueCAs[i]))
			return
		}
	}

	if len(result.IssueWildCAs) != len(assertres.IssueWildCAs) {
		body = []byte("Issue CAs count mismatch")
		return
	}

	for i := range result.IssueWildCAs {
		if result.IssueWildCAs[i] != assertres.IssueWildCAs[i] {
			body = []byte(fmt.Sprintf(`Issue CAs mismatch %s != %s`,
				result.IssueWildCAs[i], assertres.IssueWildCAs[i]))
			return
		}
	}

	pass = true
	return
}

func (e eval) AnalysisPrinter(input []byte, printAll interface{}) (results []string, err error) {
	var r Result
	err = json.Unmarshal(input, &r)
	if err != nil {
		err = fmt.Errorf("CAA worker: failed to parse results: %v", err)
		return
	}

	if !r.HasCAA {
		results = append(results, "* CAA records: not found")
	} else {
		results = append(results, "* CAA records: found")
		for _, issue := range r.IssueCAs {
			results = append(results, fmt.Sprintf("  - CA '%s' permitted to issue certs for '%s'", issue, r.Host))
		}
		for _, wild := range r.IssueWildCAs {
			results = append(results, fmt.Sprintf("  - CA '%s' permitted to issue wildcard certs for '%s'", wild, r.Host))
		}
	}

	return results, nil
}
