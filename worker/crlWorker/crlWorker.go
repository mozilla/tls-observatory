package crlWorker

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"sync"
	"time"

	"github.com/mozilla/tls-observatory/certificate"
	"github.com/mozilla/tls-observatory/worker"
)

var (
	workerName = "crlWorker"
	workerDesc = "Checks certificate CRL (Certificate Revocation List) and reports on certificate revocation"

	httpClient = &http.Client{
		Timeout: 30 * time.Second,
	}
)

type Result struct {
	RevocationTime time.Time
	Revoked bool `json:"revoked"`
}

type eval struct{}

// Run implements the worker.Worker interface and is called check CRL status
func (e eval) Run(in worker.Input, resChan chan worker.Result) {
	result := worker.Result{
		WorkerName: workerName,
	}
	crlRes := Result{}

	// Grab first CRL response we can from our certificate
	crlResponses, err := getCRLResponses(in.Certificate)
	if err != nil {
		resChan <- worker.Result{
			Success:    false,
			WorkerName: workerName,
			Errors:     []string{fmt.Sprintf("error getting CRL response, err=%v", err)},
			Result:     nil,
		}
		return
	}
	if len(crlResponses) == 0 {
		resChan <- worker.Result{
			Success:    false,
			WorkerName: workerName,
			Errors:     []string{fmt.Sprintf("no CRL responses received, err=%v", err)},
			Result:     nil,
		}
		return
	}

	// TODO(adam): store all CRL responses
	// TODO(adam): Process all responses? Or just one that's signed?
	certList, err := x509.ParseCRL(crlResponses[0])
	if err != nil {
		resChan <- worker.Result{
			Success:    false,
			WorkerName: workerName,
			Errors:     []string{fmt.Sprintf("error reading CRL response for %s", in.Certificate.ID)},
			Result:     nil,
		}
		return
	}

	// Verify the CRL
	if err = verifyCRL(certList, in.Certificate, in.CertificateChain); err != nil {
		resChan <- worker.Result{
			Success:    false,
			WorkerName: workerName,
			Errors:     []string{fmt.Sprintf("error verifying CRL, err=%v", err)},
			Result:     nil,
		}
		return
	}

	x509Cert, err := in.Certificate.ToX509()
	if err != nil {
		resChan <- worker.Result{
			Success:    false,
			WorkerName: workerName,
			Errors:     []string{fmt.Sprintf("error converting Certificate %s to x509.Certificate, err=%v", in.Certificate.ID, err)},
			Result:     nil,
		}
		return
	}

	// Check if our certificate is in the revoked list
	revoked := certList.TBSCertList.RevokedCertificates
	for i := range revoked {
		if x509Cert.SerialNumber.Cmp(revoked[i].SerialNumber) == 0 {
			// certificate is in revoked list, serials match
			crlRes.RevocationTime = certList.TBSCertList.ThisUpdate
			crlRes.Revoked = true
			break
		}
	}

	// Marshal the response
	bs, err := json.Marshal(&crlRes)
	if err != nil {
		result.Success = false
		result.Errors = append(result.Errors, err.Error())
	} else {
		result.Success = true
		result.Result = bs
	}
	// TODO "I think it'd be useful to add a column to the certificate table to store the fact it has been revoked via CRL."
	resChan <- result
}

// Grab the first CRL response and return it in raw bytes
func getCRLResponses(cert certificate.Certificate) ([][]byte, error) {
	var wg sync.WaitGroup
	var out [][]byte

	crlPoints := cert.X509v3Extensions.CRLDistributionPoints
	wg.Add(len(crlPoints))
	for i := range crlPoints {
		go func(point string, wg *sync.WaitGroup) {
			defer wg.Done()

			resp, err := httpClient.Get(point)
			if err != nil {
				return
			}
			defer resp.Body.Close()
			bs, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				return
			}
			out = append(out, bs)
		}(crlPoints[i], &wg)
	}
	wg.Wait()

	if len(out) > 0 {
		return out, nil
	}
	return nil, fmt.Errorf("Unable to load CRL data for certificate %s", cert.Subject)
}

func verifyCRL(certList *pkix.CertificateList, cert certificate.Certificate, chain *certificate.Chain) error {
	for i := range chain.Certs {
		// each cert is a base64 DER encoded certificate
		raw, err := base64.StdEncoding.DecodeString(chain.Certs[i])
		if err != nil {
			return fmt.Errorf("error decoding base64 DER of Certificate from %s chain, err=%v", chain.Domain, err)
		}

		block, _ := pem.Decode([]byte(raw))
		if block == nil {
			return fmt.Errorf("error reading DER of Certificate from %s chain, err=%v", chain.Domain, err)
		}
		if block.Type != "CERTIFICATE" {
			return fmt.Errorf("Unknown block %s in %s chain", block.Type, chain.Domain)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("error reading certificate, err=%v", err)
		}

		// Check if cert signed the CRL response
		if err := cert.CheckCRLSignature(certList); err == nil {
			return nil // cert signed our CRL
		}
	}
	return fmt.Errorf("Unable to verify CRL against %s chain", chain.Domain)
}

// AnalysisPrinter outputs results of comparing a certificate against the CRL(s) contained within
func (eval) AnalysisPrinter(input []byte, printAll interface{}) (results []string, err error) {
	var result Result
	if err := json.Unmarshal(input, &result); err != nil {
		return results, fmt.Errorf("CRL Worker: failed to parse results: err=%v", err)
	}

	if result.Revoked {
		results = append(results, fmt.Sprintf("* Certificate: Revoked (at %s)", result.RevocationTime.String()))
	} else {
		results = append(results, "* Certificate: Not Revoked")
	}

	return results, nil
}
