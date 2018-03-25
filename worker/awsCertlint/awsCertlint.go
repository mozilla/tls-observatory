package awsCertlint

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"

	"github.com/mozilla/tls-observatory/certificate"
	"github.com/mozilla/tls-observatory/worker"
)

var (
	workerName = "awsCertlint"
	workerDesc = "Runs awslabs/certlint over a given Certificate, categoriezes output for display on the certificate"

	certlintDirectory = "/go/certlint" // path from tools/Dockerfile-scanner
)

type Result struct {
	Bugs []string `json:"Bugs"`
	Informational []string `json:"Informational"`
	Notices []string `json:"Notices"`
	Warnings []string `json:"Warnings"`
	Errors []string `json:"Errors"`
	FatalErrors []string `json:"FatalErrors"`
}

func init() {
	runner := new(eval)
	worker.RegisterWorker(workerName, worker.Info{Runner: runner, Description: workerDesc})
}

type eval struct{}

func (e eval) Run(in worker.Input, resChan chan worker.Result) {
	result := worker.Result{
		WorkerName: workerName,
	}
	lintResult, err := e.runCertlint(in.Certificate)
	if err != nil {
		resChan <- worker.Result{
			Success:    false,
			WorkerName: workerName,
			Errors:     []string{fmt.Sprintf("%s for certificate %s", err.Error(), in.Certificate.ID)},
			Result:     nil,
		}
		return
	}

	// Marshal the response
	bs, err := json.Marshal(&lintResult)
	if err != nil {
		result.Success = false
		result.Errors = append(result.Errors, err.Error())
	} else {
		result.Success = true
		result.Result = bs
	}
	resChan <- result
}

func (e eval) runCertlint(cert certificate.Certificate) (*Result, error) {
	tmp, err := ioutil.TempFile("", "awslabs-certlint")
	if err != nil {
		return nil, fmt.Errorf("error creating temp dir", cert.ID)
	}
	defer os.Remove(tmp.Name())
	x509Cert, err := cert.ToX509()
	if err != nil {
		return nil, fmt.Errorf("error converting to x509.Certificate", cert.ID)
	}
	if err := ioutil.WriteFile(tmp.Name(), x509Cert.Raw, 0644); err != nil {
		return nil, fmt.Errorf("error writing x509.Certificate to temp file, err=%v", err)
	}

	// Run certlint over certificate
	cmd := exec.Command("ruby", "-I", "lib:ext", "bin/certlint", tmp.Name())
	cmd.Dir = certlintDirectory

	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	// attach stdout/stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("error running awslabs/certlint, err=%v, out=%q", cert.ID, strings.TrimSpace(stderr.String()))
	}

	return e.parseResponse(stdout)
}


// From: https://github.com/awslabs/certlint#output
//
// * B: Bug. Your certificate has a feature not handled by certlint.
// * I: Information.  These are purely informational; no action is needed.
// * N: Notice.  These are items known to cause issues with one or more implementations of certificate processing but are not errors according to the standard.
// * W: Warning.  These are issues where a standard recommends differently but the standard uses terms such as "SHOULD" or "MAY".
// * E: Error.  These are issues where the certificate is not compliant with the standard.
// * F: Fatal Error.  These errors are fatal to the checks and prevent most further checks from being executed.  These are extremely bad errors.
func (e eval) parseResponse(resp bytes.Buffer) (*Result, error) {
	out := &Result{}

	r := bufio.NewScanner(&resp)
	for r.Scan() {
		line := strings.TrimSpace(r.Text())
		if line == "" {
			continue
		}

		// Match first letter of each line, which signifies its type.
		switch line[0] {
		case 'B':
			out.Bugs = append(out.Bugs, strings.TrimSpace(line[2:]))
		case 'I':
			out.Informational = append(out.Informational, strings.TrimSpace(line[2:]))
		case 'N':
			out.Notices = append(out.Notices, strings.TrimSpace(line[2:]))
		case 'W':
			out.Warnings = append(out.Warnings, strings.TrimSpace(line[2:]))
		case 'E':
			out.Errors = append(out.Errors, strings.TrimSpace(line[2:]))
		case 'F':
			out.FatalErrors = append(out.FatalErrors, strings.TrimSpace(line[2:]))
		}
	}
	return out, nil
}

// AnalysisPrinter outputs the results from awslabs/certlint over a given certificate
func (e eval) AnalysisPrinter(input []byte, printAll interface{}) (results []string, err error) {
	var result Result
	if err := json.Unmarshal(input, &result); err != nil {
		return nil, fmt.Errorf("awsCertlint Worker: failed to parse results: err=%v", err)
	}

	// Build results for webview
	results = append(results, "* awslabs/certlint Results")
	for i := range result.FatalErrors {
		results = append(results, fmt.Sprintf(" - Fatal Error: %s", result.FatalErrors[i]))
	}
	for i := range result.Errors {
		results = append(results, fmt.Sprintf(" - Error: %s", result.Errors[i]))
	}
	for i := range result.Warnings {
		results = append(results, fmt.Sprintf(" - Warning: %s", result.Warnings[i]))
	}
	for i := range result.Informational {
		results = append(results, fmt.Sprintf(" - Information: %s", result.Informational[i]))
	}
	for i := range result.Notices {
		results = append(results, fmt.Sprintf(" - Notice: %s", result.Notices[i]))
	}
	for i := range result.Bugs {
		results = append(results, fmt.Sprintf(" - Bug: %s", result.Bugs[i]))
	}
	if len(results) == 1 {
		results = append(results, " - No messages")
	}
	return results, nil
}
