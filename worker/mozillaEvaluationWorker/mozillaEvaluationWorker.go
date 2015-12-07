package mozillaEvaluationWorker

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/mozilla/tls-observatory/connection"
	"github.com/mozilla/tls-observatory/logger"
	"github.com/mozilla/tls-observatory/worker"
)

var workerName = "mozillaEvaluationWorker"
var workerDesc = `The evaluation worker provided insight on the compliance level of the tls configuration of the audited target.
For more info check https://wiki.mozilla.org/Security/Server_Side_TLS.`

var modern, intermediate, old Configuration

var log = logger.GetLogger()

func init() {
	err := json.Unmarshal([]byte(oldC), &old)
	if err != nil {
		log.Error("Could not load old configuration. Evaluation Worker not available")
		return
	}
	err = json.Unmarshal([]byte(modernC), &modern)
	if err != nil {
		log.Error("Could not load modern configuration. Evaluation Worker not available")
		return
	}
	err = json.Unmarshal([]byte(intermediateC), &intermediate)
	if err != nil {
		log.Error("Could not load intermediate configuration. Evaluation Worker not available")
		return
	}
	worker.RegisterWorker(workerName, worker.Info{Runner: new(eval), Description: workerDesc})
}

// Configuration represents configurations levels declared by the Mozilla server-side-tls
// see https://wiki.mozilla.org/Security/Server_Side_TLS
type Configuration struct {
	Ciphersuite          string   `json:"ciphersuite"`
	Ciphers              []string `json:"ciphers"`
	TLSVersions          []string `json:"tls_versions"`
	TLSCurves            []string `json:"tls_curves"`
	CertificateType      string   `json:"certificate_type"`
	CertificateCurve     string   `json:"certificate_curve"`
	CertificateSignature string   `json:"certificate_signature"`
	RsaKeySize           float64  `json:"rsa_key_size"`
	DhParamSize          float64  `json:"dh_param_size"`
	Hsts                 string   `json:"hsts"`
	OldestClients        []string `json:"oldest_clients"`
}

// EvaluationResults contains the results of the mozillaEvaluationWorker
type EvaluationResults struct {
	Level    string              `json:"level"`
	Failures map[string][]string `json:"failures"`
}

type eval struct {
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

	var isO, isI, isM, isB bool

	results := EvaluationResults{}
	results.Failures = make(map[string][]string)

	isO, results.Failures["old"] = isOld(connInfo)
	if isO {
		results.Level = "old"

		ord, ordres := isOrdered(connInfo, old.Ciphers, "old")
		if !ord {
			results.Level += " with bad ordering"
			results.Failures["old"] = append(results.Failures["old"], ordres...)
		}
	}

	isI, results.Failures["intermediate"] = isIntermediate(connInfo)
	if isI {
		results.Level = "intermediate"

		ord, ordres := isOrdered(connInfo, intermediate.Ciphers, "intermediate")
		if !ord {
			results.Level += " with bad ordering"
			results.Failures["intermediate"] = append(results.Failures["intermediate"], ordres...)
		}
	}

	isM, results.Failures["modern"] = isModern(connInfo)
	if isM {
		results.Level = "modern"

		ord, ordres := isOrdered(connInfo, modern.Ciphers, "modern")
		if !ord {
			results.Level += " with bad ordering"
			results.Failures["modern"] = append(results.Failures["modern"], ordres...)
		}
	}

	isB, results.Failures["bad"] = isBad(connInfo)
	if isB {
		results.Level = "bad"
	}

	fmt.Println(isB, isO, isI, isM)

	js, err := json.Marshal(results)
	if err != nil {
		return nil, err
	}

	return js, nil
}

func isBad(c connection.Stored) (bool, []string) {

	var failures, allProtos, allCiphers []string
	status := false
	hasSSLv2 := false
	hasBadPFS := false
	hasBadPK := false
	hasMD5 := false

	for _, cs := range c.CipherSuite {

		allCiphers = append(allCiphers, cs.Cipher)

		if contains(cs.Protocols, "SSLv2") {
			hasSSLv2 = true
		}

		for _, proto := range cs.Protocols {
			if !contains(allProtos, proto) {
				allProtos = append(allProtos, proto)
			}
		}

		if cs.PFS != "None" {
			if !hasGoodPFS(cs.PFS, 1024, 160, false) {
				hasBadPFS = true
			}
		}

		if cs.PubKey < 2048 {
			hasBadPK = true
		}

		if cs.SigAlg == "md5WithRSAEncryption" {
			hasMD5 = true
		}
	}

	badCiphers := extra(old.Ciphers, allCiphers)
	if len(badCiphers) > 0 {
		for _, c := range badCiphers {
			failures = append(failures, fmt.Sprintf("remove cipher %s", c))
			status = true
		}
	}

	if hasSSLv2 {
		failures = append(failures, "disable SSLv2")
		status = true
	}

	if hasBadPFS {
		failures = append(failures, "don't use DHE smaller than 1024bits or ECC smaller than 160bits")
		status = true
	}

	if hasBadPK {
		failures = append(failures, "don't use a public key shorter than 2048bit")
		status = true
	}

	if hasMD5 {
		failures = append(failures, "don't use an MD5 signature")
		status = true
	}

	return status, failures
}

func isOld(c connection.Stored) (bool, []string) {

	status := true
	var allProtos []string
	hasSHA1 := true
	has3DES := false
	hasSSLv3 := false
	hasOCSP := true
	hasPFS := true
	var failures []string

	for _, cs := range c.CipherSuite {

		if !contains(modern.Ciphers, cs.Cipher) {
			failures = append(failures, fmt.Sprintf("remove %s cipher", cs.Cipher))
			status = false
		}

		if cs.Cipher == "DES-CBC3-SHA" {
			has3DES = true
		}

		if contains(cs.Protocols, "SSLv3") {
			hasSSLv3 = true
		}

		for _, proto := range cs.Protocols {
			if !contains(allProtos, proto) {
				allProtos = append(allProtos, proto)
			}
		}

		if cs.PFS != "None" {
			if !hasGoodPFS(cs.PFS, 1024, 256, true) {
				hasPFS = false
				status = false
			}
		}

		if cs.SigAlg != old.CertificateSignature {

			fail := fmt.Sprintf("%s is not an old signature", cs.SigAlg)
			if !contains(failures, fail) {
				failures = append(failures, fail)
			}

			hasSHA1 = false
			status = false
		}

		if !cs.OCSPStapling {
			hasOCSP = false
			status = false
		}
	}

	extraProto := extra(old.TLSVersions, allProtos)
	for _, p := range extraProto {
		failures = append(failures, fmt.Sprintf("disable %s protocol", p))
		status = false
	}

	missingProto := extra(allProtos, old.TLSVersions)
	for _, p := range missingProto {
		failures = append(failures, fmt.Sprintf("consider enabling %s", p))
	}

	if !c.ServerSide {
		failures = append(failures, "enforce ServerSide ordering")
	}

	if !hasSSLv3 {
		failures = append(failures, "add SSLv3 support")
	}

	if !hasOCSP {
		failures = append(failures, "consider enabling OCSP stapling")
	}

	if !hasSHA1 {
		failures = append(failures, "it is recommended to use sha1")
	}

	if !has3DES {
		failures = append(failures, "add cipher DES-CBC3-SHA")
	}

	if !hasPFS {
		failures = append(failures, "use DHE of at least 2048bits and ECC of at least 256bits")
	}

	return status, failures
}

func isIntermediate(c connection.Stored) (bool, []string) {

	status := true
	var allProtos []string
	hasTLSv1 := false
	hasAES := false
	hasSHA256 := true
	hasOCSP := true
	hasPFS := true
	var failures []string

	for _, cs := range c.CipherSuite {

		if !contains(intermediate.Ciphers, cs.Cipher) {
			failures = append(failures, fmt.Sprintf("remove %s cipher", cs.Cipher))
			status = false
		}

		for _, proto := range cs.Protocols {
			if !contains(allProtos, proto) {
				allProtos = append(allProtos, proto)
			}
		}

		if contains(cs.Protocols, "TLSv1") {
			hasTLSv1 = true
		}

		if cs.Cipher == "AES128-SHA" {
			hasAES = true
		}

		if cs.PFS != "None" {
			if !hasGoodPFS(cs.PFS, 2048, 256, false) {
				hasPFS = false
				status = false
			}
		}

		if cs.SigAlg != intermediate.CertificateSignature {

			fail := fmt.Sprintf("%s is not an intermediate signature", cs.SigAlg)
			if !contains(failures, fail) {
				failures = append(failures, fail)
			}
			hasSHA256 = false
			status = false
		}

		if !cs.OCSPStapling {
			hasOCSP = false
			status = false
		}
	}

	extraProto := extra(intermediate.TLSVersions, allProtos)
	for _, p := range extraProto {
		failures = append(failures, fmt.Sprintf("disable %s protocol", p))
		status = false
	}

	if !hasAES {
		failures = append(failures, "add cipher AES128-SHA")
		status = false
	}

	if !hasTLSv1 {
		failures = append(failures, "consider adding TLSv1")
		status = false
	}

	if !c.ServerSide {
		failures = append(failures, "enforce ServerSide ordering")
	}

	if !hasOCSP {
		failures = append(failures, "consider enabling OCSP stapling")
	}

	if !hasSHA256 {
		failures = append(failures, "it is recommended to use sha256")
	}

	if !hasPFS {
		failures = append(failures, "use DHE of at least 2048bits and ECC of at least 256bits")
	}

	return status, failures
}

func isModern(c connection.Stored) (bool, []string) {

	status := true
	var allProtos []string
	hasSHA256 := true
	hasOCSP := true
	hasPFS := true
	var failures []string

	for _, cs := range c.CipherSuite {

		if !contains(modern.Ciphers, cs.Cipher) {
			failures = append(failures, fmt.Sprintf("remove %s cipher", cs.Cipher))
			status = false
		}

		for _, proto := range cs.Protocols {
			if !contains(allProtos, proto) {
				allProtos = append(allProtos, proto)
			}
		}

		if cs.PFS != "None" {
			if !hasGoodPFS(cs.PFS, 2048, 256, false) {
				hasPFS = false
				status = false
			}
		}

		if cs.SigAlg != modern.CertificateSignature {
			fail := fmt.Sprintf("%s is not a modern signature", cs.SigAlg)
			if !contains(failures, fail) {
				failures = append(failures, fail)
			}
			hasSHA256 = false
			status = false
		}

		if !cs.OCSPStapling {
			hasOCSP = false
			status = false
		}
	}

	extraProto := extra(modern.TLSVersions, allProtos)
	for _, p := range extraProto {
		failures = append(failures, fmt.Sprintf("disable %s protocol", p))
		status = false
	}

	if !c.ServerSide {
		failures = append(failures, "enforce ServerSide ordering")
	}

	if !hasOCSP {
		failures = append(failures, "consider enabling OCSP stapling")
	}

	if !hasSHA256 {
		failures = append(failures, "it is recommended to use sha256")
	}

	if !hasPFS {
		failures = append(failures, "use DHE of at least 2048bits and ECC of at least 256bits")
	}
	return status, failures
}

func isOrdered(c connection.Stored, conf []string, level string) (bool, []string) {

	var failures []string
	status := true
	prevpos := 0
	for _, ciphersuite := range c.CipherSuite {
		for pos, cipher := range conf {
			if ciphersuite.Cipher == cipher {
				if pos < prevpos {
					failures = append(failures, fmt.Sprintf("increase priority of %s over %s", ciphersuite.Cipher, conf[prevpos]))
					status = false
				}
				prevpos = pos
			}
		}
	}
	if !status {
		failures = append(failures, fmt.Sprintf("fix ciphersuite ordering, use recommended %s ciphersuite", level))
	}
	return status, failures
}

func hasGoodPFS(curPFS string, targetDH, targetECC int, mustMatch bool) bool {

	pfs := strings.Split(curPFS, ",")
	if len(pfs) < 2 {
		return false
	}

	if "ECDH" == pfs[0] {
		bitsStr := strings.TrimRight(pfs[2], "bits")

		bits, err := strconv.Atoi(bitsStr)
		if err != nil {
			return false
		}

		if !mustMatch {
			if bits < targetECC {
				return false
			}
		} else {
			if bits != targetECC {
				return false
			}
		}

	} else if "DH" == pfs[0] {
		bitsStr := strings.TrimRight(pfs[1], "bits")

		bits, err := strconv.Atoi(bitsStr)
		if err != nil {
			return false
		}

		if !mustMatch {
			if bits < targetDH {
				return false
			}
		} else {
			if bits != targetDH {
				return false
			}
		}
	} else {
		return false
	}
	return true
}

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func extra(s []string, e []string) []string {

	var extra []string

	for _, str := range e {
		if !contains(s, str) {
			extra = append(extra, str)
		}
	}
	return extra
}
