package awsCertlint

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/mozilla/tls-observatory/certificate"
	"github.com/mozilla/tls-observatory/logger"
	"github.com/mozilla/tls-observatory/worker"
)

var (
	workerName = "awsCertlint"
	workerDesc = "Runs the awslabs certificate linter and saves output"

	certlintDirectory = "/go/certlint" // path from tools/Dockerfile-scanner
	binaryPath        = "bin/certlint" // path inside `certlintDirectory`

	log = logger.GetLogger()
)

type Result struct {
	Bugs          []string `json:"bugs"`
	Informational []string `json:"informational"`
	Notices       []string `json:"notices"`
	Warnings      []string `json:"warnings"`
	Errors        []string `json:"errors"`
	FatalErrors   []string `json:"fatalErrors"`
}

func init() {
	runner := new(eval)
	worker.RegisterPrinter(workerName, worker.Info{Runner: runner, Description: workerDesc})

	// override certlintDirectory if TLS_AWSCERTLINT_DIR
	if path := os.Getenv("TLS_AWSCERTLINT_DIR"); path != "" {
		certlintDirectory = path
	}

	// Verify code was pulled down
	fullPath := filepath.Join(certlintDirectory, binaryPath)
	_, err := os.Stat(fullPath)
	if err != nil && os.IsNotExist(err) {
		log.Debugf("Could not find awslabs/certlint (tried %q), disabling worker\n", fullPath)
		return
	}
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
			Errors:     []string{fmt.Sprintf("%s for certificate %d", err.Error(), in.Certificate.ID)},
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
		return nil, fmt.Errorf("error creating temp file for certificate %d", cert.ID)
	}
	defer os.Remove(tmp.Name())
	x509Cert, err := cert.ToX509()
	if err != nil {
		return nil, fmt.Errorf("error converting certificate %d to x509.Certificate", cert.ID)
	}
	if err := ioutil.WriteFile(tmp.Name(), x509Cert.Raw, 0644); err != nil {
		return nil, fmt.Errorf("error writing x509.Certificate to temp file, err=%v", err)
	}

	// Run certlint over certificate
	cmd := exec.Command("ruby", "-I", "lib:ext", binaryPath, tmp.Name())
	cmd.Dir = certlintDirectory

	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("error starting awslabs/certlint on certificate %d, err=%v, out=%q", cert.ID, err, strings.TrimSpace(stderr.String()))
	}

	waitChan := make(chan error, 1)
	go func() {
		waitChan <- cmd.Wait()
	}()

	select {
	case <-time.After(30 * time.Second):
		err := cmd.Process.Kill()
		return nil, fmt.Errorf("timed out waiting for awslabs/certlint on certificate %d, kill error=%v", cert.ID, err)
	case err := <-waitChan:
		if err != nil {
			return nil, fmt.Errorf("error running awslabs/certlint on certificate %d, err=%v, out=%q", cert.ID, err, strings.TrimSpace(stderr.String()))
		}
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

	// Add header and summary as first two lines
	headers := []string{
		"* awslabs/certlint",
	}

	// We only want one summary line, so match in order of severity
	switch true {
	case len(result.FatalErrors) > 0 || len(result.Errors) > 0:
		headers = append(headers, fmt.Sprintf(" - %d errors, %d fatal", len(result.Errors), len(result.FatalErrors)))
	case len(result.Warnings) > 0:
		headers = append(headers, fmt.Sprintf(" - %d warnings found", len(result.Warnings)))
	}

	// Add header(s) as first line, print notice if nothing was found
	results = append(headers, results...)
	if len(results) == 1 {
		results = append(results, " - No messages")
	}
	return results, nil
}
