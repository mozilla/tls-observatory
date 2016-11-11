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
)

var workerName = "evCheckerWorker"
var workerDesc = `Provides insights for EV certificates`

var log = logger.GetLogger()

func init() {
	worker.RegisterWorker(workerName, worker.Info{Runner: new(evWorker), Description: workerDesc})
}

type evWorker struct{}

func (w evWorker) Run(in worker.Input, res chan worker.Result) {
	scan, err := in.DBHandle.GetScanByID(in.Scanid)
	if err != nil {
		w.error("Could not get scan: %s", err, res)
		return
	}

	params := reflect.ValueOf(in.Params)
	if params.Kind() != reflect.Map {
		w.error("%s", fmt.Errorf("Invalid parameters passed to evWorker: %s", params), res)
		return
	}
	var oid string
	for _, k := range params.MapKeys() {
		if k.Interface() == "oid" {
			var ok bool
			oid, ok = params.MapIndex(k).Interface().(string)
			if !ok {
				w.error("%s", fmt.Errorf("Could not cast oid to string"), res)
			}
		}
	}
	fmt.Println("oid:", oid)
	certs, err := in.DBHandle.GetAllCertsInChain(in.Certificate.ID)
	if err != nil {
		w.error("Could not get all certificates in chain: %s", err, res)
		return
	}
	var buffer bytes.Buffer
	for i := len(certs) - 1; i >= 0; i-- {
		cert, err := certs[i].ToX509()
		if err != nil {
			w.error("Could not convert certificate to X509: %s", err, res)
			return
		}
		err = pem.Encode(&buffer, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
		if err != nil {
			w.error("Error PEM-encoding certificate", err, res)
			return
		}
	}
	file, err := ioutil.TempFile("", "")
	if err != nil {
		w.error("Could not create temporary file to write certificates: %s", err, res)
		return
	}
	defer file.Close()
	_, err = buffer.WriteTo(file)
	if err != nil {
		w.error("Could not write certificates to temporary file: %s", err, res)
		return
	}
	fmt.Println("ev-checker", "-o", oid, "-h", scan.Target, "-c", file.Name())
	cmd := exec.Command("ev-checker", "-o", oid, "-h", scan.Target, "-c", file.Name())
	_, err = cmd.Output()
	if err != nil {
		w.error("Could not get output from ev-checker: %s", err, res)
		return
	}
	res <- worker.Result{
		Success:    true,
		WorkerName: workerName,
		Errors:     nil,
		Result:     []byte(`"Success"`),
	}
}

func (w evWorker) error(messageFormat string, err error, res chan worker.Result) {
	res <- worker.Result{
		Success:    false,
		WorkerName: workerName,
		Errors: []string{
			fmt.Sprintf(messageFormat, err),
		},
	}
}
