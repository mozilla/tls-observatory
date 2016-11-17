package evCheckerWorker

import (
	"bytes"
	"encoding/pem"
	"fmt"
	"github.com/mozilla/tls-observatory/logger"
	"github.com/mozilla/tls-observatory/worker"
	"io/ioutil"
	"os/exec"
	"reflect"
	"os"
)

var workerName = "evCheckerWorker"
var workerDesc = `Determines if a given EV policy fulfills the requirements of Mozilla's Root CA program.`

var log = logger.GetLogger()

func init() {
	if _, err := os.Lstat(EvCheckerBinaryName); err != nil {
		log.Warn("Could not find ev-checker binary, " + EvCheckerBinaryName + " disabled.")
		return
	}
	worker.RegisterWorker(workerName, worker.Info{Runner: new(evWorker), Description: workerDesc})
}

type evWorker struct{
	Binary string
}

func (w evWorker) Run(in worker.Input, res chan worker.Result) {
	scan, err := in.DBHandle.GetScanByID(in.Scanid)
	if err != nil {
		w.error(res, "Could not get scan: %s", err)
		return
	}

	params := reflect.ValueOf(in.Params)
	if params.Kind() != reflect.Map {
		w.error(res, "%s", fmt.Errorf("Invalid parameters passed to evWorker: %s", params))
		return
	}
	var oid string
	for _, k := range params.MapKeys() {
		if k.Interface() == "oid" {
			var ok bool
			oid, ok = params.MapIndex(k).Interface().(string)
			if !ok {
				w.error(res, "%s", fmt.Errorf("Could not cast oid to string"))
			}
		}
	}
	certs, err := in.DBHandle.GetAllCertsInChain(in.Certificate.ID)
	if err != nil {
		w.error(res, "Could not get all certificates in chain: %s", err)
		return
	}
	var buffer bytes.Buffer
	// Iterate over the certificates in reverse because the root certificate
	// has to be emitted last.
	for i := len(certs) - 1; i >= 0; i-- {
		cert, err := certs[i].ToX509()
		if err != nil {
			w.error(res, "Could not convert certificate to X509: %s", err)
			return
		}
		err = pem.Encode(&buffer, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
		if err != nil {
			w.error(res, "Error PEM-encoding certificate", err)
			return
		}
	}
	file, err := ioutil.TempFile("", "")
	if err != nil {
		w.error(res, "Could not create temporary file to write certificates: %s", err)
		return
	}
	defer file.Close()
	defer os.Remove(file.Name())
	_, err = buffer.WriteTo(file)
	if err != nil {
		w.error(res, "Could not write certificates to temporary file: %s", err)
		return
	}
	cmd := exec.Command(EvCheckerBinaryName, "-o", oid, "-h", scan.Target, "-c", file.Name())
	_, err = cmd.Output()
	if err != nil {
		w.error(res, "Could not get output from ev-checker: %s", err)
		return
	}
	res <- worker.Result{
		Success:    true,
		WorkerName: workerName,
		Errors:     nil,
		Result:     []byte(`"Success"`),
	}
}

func (w evWorker) error(res chan worker.Result, messageFormat string, err error) {
	res <- worker.Result{
		Success:    false,
		WorkerName: workerName,
		Errors: []string{
			fmt.Sprintf(messageFormat, err),
		},
	}
}
