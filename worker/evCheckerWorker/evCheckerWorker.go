package evCheckerWorker

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"regexp"

	"encoding/base64"
	"encoding/pem"

	"github.com/mozilla/tls-observatory/logger"
	"github.com/mozilla/tls-observatory/worker"
)

var workerName = "ev-checker"
var workerDesc = `Determines if a given EV policy fulfills the requirements of Mozilla's Root CA program.`

var log = logger.GetLogger()

func init() {
	runner := new(evWorker)
	worker.RegisterPrinter(workerName, worker.Info{Runner: runner, Description: workerDesc})

	if path := os.Getenv("TLSOBS_EVCHECKERPATH"); path != "" {
		EvCheckerBinaryName = path
	}
	_, err := exec.LookPath(EvCheckerBinaryName)
	if err != nil {
		log.Warn("Could not find ev-checker binary, " + workerName + " disabled.")
		return
	}
	worker.RegisterWorker(workerName, worker.Info{Runner: runner, Description: workerDesc})
}

type evWorker struct {
	Binary string
}

type params struct {
	OID             string
	RootCertificate string
}

var portRe = regexp.MustCompile("(.*):([0-9]{1,})$")

func (w evWorker) Run(in worker.Input, res chan worker.Result) {
	if portRe.MatchString(in.Target) {
		w.error(res, "EV check does not run on target that have a port specified")
		return
	}
	scan, err := in.DBHandle.GetScanByID(in.Scanid)
	if err != nil {
		w.error(res, "Could not get scan: %s", err)
		return
	}
	out, err := json.Marshal(in.Params)
	if err != nil {
		w.error(res, "Could not marshal parameters to JSON: %s", err)
	}
	var params params
	err = json.Unmarshal(out, &params)
	if err != nil {
		w.error(res, "Could not map parameters to struct: %s", err)
	}
	if params.OID == "" {
		w.error(res, "Missing OID parameter, skipping EV check")
		return
	}

	file, err := ioutil.TempFile("", "")
	for _, cert := range in.CertificateChain.Certs {
		cert, err := base64.StdEncoding.DecodeString(cert)
		if err != nil {
			w.error(res, "Could not base64-decode certificate: %s", err)
			return
		}
		err = pem.Encode(file, &pem.Block{Type: "CERTIFICATE", Bytes: cert})
		if err != nil {
			w.error(res, "Could not pem encode certificate: %s", err)
			return
		}
	}
	file.Write([]byte(params.RootCertificate))
	if err != nil {
		w.error(res, "Could not create temporary file to write certificates: %s", err)
		return
	}
	defer file.Close()
	if err != nil {
		w.error(res, "Could not write certificates to temporary file: %s", err)
		return
	}
	cmd := exec.Command(EvCheckerBinaryName, "-o", params.OID, "-h", scan.Target, "-c", file.Name())
	out, err = cmd.Output()
	if exitErr, ok := err.(*exec.ExitError); ok {
		// if the command returned with a failure, consider that a success from the worker
		// point of view, and return the failure back to the client
		out, _ = json.Marshal(fmt.Sprintf("%s, Stderr: %s", exitErr, string(exitErr.Stderr)))
		res <- worker.Result{
			Success:    true,
			WorkerName: workerName,
			Errors:     nil,
			Result:     out,
		}
		return
	} else if err != nil {
		w.error(res, "Could not get output from ev-checker: %+v", err)
		return
	}
	out, _ = json.Marshal(string(out))
	res <- worker.Result{
		Success:    true,
		WorkerName: workerName,
		Errors:     nil,
		Result:     out,
	}
}

func (w evWorker) error(res chan worker.Result, messageFormat string, args ...interface{}) {
	out, _ := json.Marshal(fmt.Sprintf(messageFormat, args...))
	res <- worker.Result{
		Success:    false,
		WorkerName: workerName,
		Result:     out,
		Errors:     []string{fmt.Sprintf(messageFormat, args...)},
	}
}
