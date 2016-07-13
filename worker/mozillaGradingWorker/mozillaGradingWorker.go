package mozillaGradingWorker

import (
	"encoding/json"
	"fmt"

	"github.com/mozilla/tls-observatory/connection"
	"github.com/mozilla/tls-observatory/logger"
	"github.com/mozilla/tls-observatory/worker"
)

var workerName = "mozillaGradingWorker"
var workerDesc = `The grading worker provides an SSLabs-like grade for the TLS configuration of
the audited target`

// EvaluationResults contains the results of the mozillaEvaluationWorker
type EvaluationResults struct {
	Grade    float64  `json:"grade"`
	Failures []string `json:"failures"`
}

type categoryResults struct {
	Grade          int
	MaximumAllowed int
	Remarks        []string
	Fail           bool
}

type CipherSuite struct {
	Proto string     `json:"proto"`
	Kx    string     `json:"kx"`
	Au    string     `json:"au"`
	Enc   Encryption `json:"encryption"`
	Mac   string     `json:"mac"`
}

type Encryption struct {
	Cipher string `json:"cipher"`
	Bits   int    `json:"key"`
}

type eval struct {
}

var opensslciphersuites = make(map[string]CipherSuite)
var log = logger.GetLogger()

func init() {
	log.Debug("Registering Grading...")
	err := json.Unmarshal([]byte(OpenSSLCiphersuites), &opensslciphersuites)
	if err != nil {
		log.Error(err)
		log.Error("Could not load OpenSSL ciphersuites. Evaluation Worker not available")
		return
	}
	worker.RegisterWorker(workerName, worker.Info{Runner: new(eval), Description: workerDesc})
}

// Run implements the worker interface.It is called to get the worker results.
func (e eval) Run(in worker.Input, resChan chan worker.Result) {

	res := worker.Result{WorkerName: workerName}

	b, err := Evaluate(in.Connection)
	if err != nil {
		res.Success = false
		res.Errors = append(res.Errors, err.Error())
	} else {
		res.Result = b
		res.Success = true
	}

	resChan <- res
}

// Evaluate runs compliance checks of the provided json Stored connection and returns the results
func Evaluate(connInfo connection.Stored) ([]byte, error) {
	protores, err := gradeProtocol(connInfo)
	if err != nil {
		return nil, err
	}
	cipherres, err := gradeCiphers(connInfo)
	if err != nil {
		return nil, err
	}

	keyxres, err := gradeKeyX(connInfo)
	if err != nil {
		return nil, err
	}

	var score float64
	score = float64(protores.Grade)*0.3 + float64(cipherres.Grade)*0.4 + float64(keyxres.Grade)*0.3

	fmt.Printf("proto : %d , cipher : %d , keyx: %d\n", int(protores.Grade), int(cipherres.Grade), int(keyxres.Grade))

	er := EvaluationResults{Grade: score}

	fmt.Printf("The Score is : %d \n", int(score))

	return json.Marshal(&er)

}

// contains checks if an entry exists in a slice and returns
// a booleans.
func contains(slice []string, entry string) bool {
	for _, element := range slice {
		if element == entry {
			return true
		}
	}
	return false
}
