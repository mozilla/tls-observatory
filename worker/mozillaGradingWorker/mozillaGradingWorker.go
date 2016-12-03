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
	Grade       float64  `json:"grade"`
	LetterGrade string   `json:"lettergrade"`
	Failures    []string `json:"failures"`
}

type categoryResults struct {
	Grade          int
	MaximumAllowed int
	Remarks        []string
}

// CipherSuite represent a ciphersuite generated and recognised by OpenSSL
type CipherSuite struct {
	IANAName   string     `json:"iana_name"`
	GnuTLSName string     `json:"gnutls_name"`
	NSSName    string     `json:"nss_name"`
	Proto      string     `json:"proto"`
	Kx         string     `json:"kx"`
	Au         string     `json:"au"`
	Enc        Encryption `json:"encryption"`
	Mac        string     `json:"mac"`
	Code       uint64     `json:"code"`
}

//Encryption represents the encryption aspects of a Ciphersuite
type Encryption struct {
	Cipher string `json:"cipher"`
	Bits   int    `json:"key"`
}

type eval struct {
}

var opensslciphersuites = make(map[string]CipherSuite)
var log = logger.GetLogger()

func init() {
	err := json.Unmarshal([]byte(OpenSSLCiphersuites), &opensslciphersuites)
	if err != nil {
		log.Error(err)
		log.Error("Could not load OpenSSL ciphersuites. Grading Worker not available")
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

	// fmt.Printf("proto : %d , cipher : %d , keyx: %d\n", int(protores.Grade), int(cipherres.Grade), int(keyxres.Grade))

	er := EvaluationResults{Grade: score, LetterGrade: getLetterfromGrade(score)}
	return json.Marshal(&er)
}

func getLetterfromGrade(grade float64) string {
	if grade < 20 {
		return "F"
	} else if grade < 35 {
		return "E"
	} else if grade < 50 {
		return "D"
	} else if grade < 65 {
		return "C"
	} else if grade < 80 {
		return "B"
	}

	return "A"
}

func (e eval) AnalysisPrinter(r []byte, targetLevel interface{}) (results []string, err error) {
	var eval EvaluationResults
	err = json.Unmarshal(r, &eval)
	if err != nil {
		err = fmt.Errorf("Mozilla grading worker: failed to parse results: %v", err)
		return
	}
	results = append(results, fmt.Sprintf("* Grade: %s (%.0f/100)",
		eval.LetterGrade, eval.Grade))
	for _, e := range eval.Failures {
		results = append(results, fmt.Sprintf("  - %s", e))
	}
	return
}

func (e eval) Assertor(evresults, assertresults []byte) (pass bool, body []byte, err error) {
	var evres, assertres EvaluationResults
	err = json.Unmarshal(evresults, &evres)
	if err != nil {
		return
	}
	err = json.Unmarshal(assertresults, &assertres)
	if err != nil {
		return
	}
	if evres.Grade != assertres.Grade {
		body = []byte(fmt.Sprintf(`Assertion mozillaGradingWorker. The domain scored %f instead of expected %f`,
			assertres.Grade, evres.Grade))
		pass = false
	} else {
		pass = true
	}
	return
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
