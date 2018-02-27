package ocspStatusWorker

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"crypto/x509"

	"github.com/mozilla/tls-observatory/logger"
	"github.com/mozilla/tls-observatory/worker"
	"golang.org/x/crypto/ocsp"
	"bytes"
	"crypto"
	"crypto/tls"
	"time"
	"encoding/base64"
)

var workerName = "ocspStatusWorker"
var workerDesc = `Determines a certificate's status via OCSP'`

var log = logger.GetLogger()

func init() {
	worker.RegisterWorker(workerName, worker.Info{Runner: new(ocspStatusWorker), Description: workerDesc})
}

type ocspStatusWorker struct {
	status OCSPStatus
}

type OCSPStatus struct {
	Status int `json:"status"`
	RevokedAt time.Time `json:"revoked_at"`

}

type params struct {
}

func (w ocspStatusWorker) Run(in worker.Input, resChan chan worker.Result) {
	res := worker.Result{WorkerName: workerName, Success:false}

	rawCert := base64.DecodeString(worker.Input.CertificateChain.Certs[0])
	certificate := x509.ParseCertificate(rawCert)
	rawIssuerCert := base64.DecodeString(worker.Input.CertificateChain.Certs[1])
	issuerCertificate := x509.ParseCertificate(rawIssuerCert)

	opts := &ocsp.RequestOptions{Hash: crypto.SHA256}
	req, err := ocsp.CreateRequest(certificate, issuerCertificate, opts)
	if err != nil {
		res.Errors = append(res.Errors, err.Error())
		return
	}

	httpResponse, err := http.Post(certificate.OCSPServer[0], "application/ocsp-request", bytes.NewReader(req))
	if err != nil {
		res.Errors = append(res.Errors, err.Error())
		return
	}

	output, err := ioutil.ReadAll(httpResponse.Body)
	if err != nil {
		res.Errors = append(res.Errors, err.Error())
		return
	}

	OCSPResponse, err := ocsp.ParseResponse(output, issuerCertificate)
	if err != nil {
		res.Errors = append(res.Errors, err.Error())
		return
	}

	status := OCSPStatus{ Status:OCSPResponse.Status, RevokedAt:OCSPResponse.RevokedAt }

	out, _ := json.Marshal(status)

	res.Success = true
	res.Result = out

	resChan <- res
}
