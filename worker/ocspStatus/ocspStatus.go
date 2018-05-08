package ocspStatus

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/mozilla/tls-observatory/logger"
	"github.com/mozilla/tls-observatory/worker"
	"golang.org/x/crypto/ocsp"
)

var (
	workerName = "ocspStatus"
	workerDesc = "Determines a certificate's status via OCSP'"

	httpClient = &http.Client{
		Transport: &http.Transport{
			TLSHandshakeTimeout: 30 * time.Second,
		},
		Timeout: 60 * time.Second,
	}

	log = logger.GetLogger()
)

func init() {
	runner := new(ocspStatus)

	worker.RegisterPrinter(workerName, worker.Info{Runner: runner, Description: workerDesc})
	worker.RegisterWorker(workerName, worker.Info{Runner: runner, Description: workerDesc})
}

type Result struct {
	Status    int       `json:"status"`
	RevokedAt time.Time `json:"revoked_at,omitempty"`
}

type ocspStatus struct{}

func (w ocspStatus) Run(in worker.Input, resChan chan worker.Result) {
	res := worker.Result{
		WorkerName: workerName,
		Success:    false,
	}

	x509Cert, err := in.Certificate.ToX509()
	if err != nil {
		resChan <- worker.Result{
			Success:    false,
			WorkerName: workerName,
			Errors:     []string{fmt.Sprintf("%s for certificate %d", err.Error(), in.Certificate.ID)},
			Result:     nil,
		}
		return
	}

	issuerEncoded := in.CertificateChain.Certs[len(in.CertificateChain.Certs)-1] // last cert in chain
	x509IssuerCertEncoded, err := base64.StdEncoding.DecodeString(issuerEncoded)
	if err != nil {
		resChan <- worker.Result{
			Success:    false,
			WorkerName: workerName,
			Errors:     []string{fmt.Sprintf("%s decoding issuer for certificate %d", err.Error(), in.Certificate.ID)},
			Result:     nil,
		}
		return
	}
	x509Issuer, err := x509.ParseCertificate(x509IssuerCertEncoded)
	if err != nil {
		resChan <- worker.Result{
			Success:    false,
			WorkerName: workerName,
			Errors:     []string{fmt.Sprintf("%s parsing issuer for certificate %d", err.Error(), in.Certificate.ID)},
			Result:     nil,
		}
		return
	}

	// grab OCSP response
	opts := &ocsp.RequestOptions{
		Hash: crypto.SHA256,
	}
	req, err := ocsp.CreateRequest(x509Cert, x509Issuer, opts)
	if err != nil {
		resChan <- worker.Result{
			Success:    false,
			WorkerName: workerName,
			Errors:     []string{fmt.Sprintf("%s creating OCSP response for certificate %d", err.Error(), in.Certificate.ID)},
			Result:     nil,
		}
		return
	}
	httpResponse, err := http.Post(x509Cert.OCSPServer[0], "application/ocsp-request", bytes.NewReader(req))
	if err != nil {
		resChan <- worker.Result{
			Success:    false,
			WorkerName: workerName,
			Errors:     []string{fmt.Sprintf("%s making OCSP response for certificate %d", err.Error(), in.Certificate.ID)},
			Result:     nil,
		}
		return
	}

	// parse response
	output, err := ioutil.ReadAll(httpResponse.Body)
	if err != nil {
		resChan <- worker.Result{
			Success:    false,
			WorkerName: workerName,
			Errors:     []string{fmt.Sprintf("%s reading OCSP response for certificate %d", err.Error(), in.Certificate.ID)},
			Result:     nil,
		}
		return
	}
	resp, err := ocsp.ParseResponse(output, x509Issuer)
	if err != nil {
		resChan <- worker.Result{
			Success:    false,
			WorkerName: workerName,
			Errors:     []string{fmt.Sprintf("%s parsing OCSP response for certificate %d", err.Error(), in.Certificate.ID)},
			Result:     nil,
		}
		return
	}

	status := Result{
		Status: resp.Status,
	}
	if resp.Status == ocsp.Revoked {
		status.RevokedAt = resp.RevokedAt
	}

	out, err := json.Marshal(status)
	if err != nil {
		res.Success = false
		res.Errors = append(res.Errors, err.Error())
	} else {
		res.Success = true
		res.Result = out
	}
	resChan <- res
}

func (ocspStatus) AnalysisPrinter(input []byte, printAll interface{}) (results []string, err error) {
	var result Result
	if err = json.Unmarshal(input, &result); err != nil {
		return nil, fmt.Errorf("ocspStatus Worker: failed to parse results: err=%v", err)
	}
	switch result.Status {
	case ocsp.Good:
		results = []string{fmt.Sprintf("* OCSP: Not revoked")}
	case ocsp.Revoked:
		results = []string{fmt.Sprintf("* OCSP: Revoked at %s", result.RevokedAt.Format(time.RFC3339))}
	default:
		results = []string{fmt.Sprintf("* OCSP: Unknown status code %d", result.Status)}
	}
	return results, nil
}
