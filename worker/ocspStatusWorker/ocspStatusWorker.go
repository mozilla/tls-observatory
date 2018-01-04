package ocspStatusWorker

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"crypto/tls"
	"crypto/x509"

	"github.com/mozilla/tls-observatory/logger"
	"github.com/mozilla/tls-observatory/worker"
	"golang.org/x/crypto/ocsp"
	"bytes"
	"crypto"
	"time"
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

func (w ocspStatusWorker) Run(in worker.Input, res chan worker.Result) {
	out, err := json.Marshal(in.Params)

	conn, err := tls.Dial("tcp", in.Connection.ScanIP + ":443", nil)
	if err != nil {w.error(res, "Could not connect to server: %s", err)}
	defer conn.Close()

	issuerCertificate := conn.ConnectionState().PeerCertificates[1]
	certificate := conn.ConnectionState().PeerCertificates[0]

	opts := &ocsp.RequestOptions{Hash: crypto.SHA256}
	req, err := ocsp.CreateRequest(certificate, issuerCertificate, opts)
	if err != nil {w.error(res, "Could not create OCSP request: %s", err)}

	httpResponse, err := http.Post(certificate.OCSPServer[0], "application/ocsp-request", bytes.NewReader(req))
	if err != nil {log.Fatal(err)}

	output, err := ioutil.ReadAll(httpResponse.Body)
	if err != nil {w.error(res, "Could not read HTTP response body: %s", err)}

	OCSPResponse, err := ocsp.ParseResponse(output, issuerCertificate)
	if err != nil {w.error(res, "Could not parse OCSP response: %s", err)}

	status := OCSPStatus{ Status:OCSPResponse.Status, RevokedAt:OCSPResponse.RevokedAt }

	out, _ = json.Marshal(status)

	res <- worker.Result{
		Success:    true,
		WorkerName: workerName,
		Errors:     nil,
		Result:     out,
	}
}

func (w ocspStatusWorker) error(res chan worker.Result, messageFormat string, args ...interface{}) {
	out, _ := json.Marshal(fmt.Sprintf(messageFormat, args...))
	res <- worker.Result{
		Success:    false,
		WorkerName: workerName,
		Result:     out,
	}
}