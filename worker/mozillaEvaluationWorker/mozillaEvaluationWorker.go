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

var sigAlgTranslation = map[string]string{
	"SHA1WithRSA":     "sha1WithRSAEncryption",
	"SHA256WithRSA":   "sha256WithRSAEncryption",
	"SHA384WithRSA":   "sha384WithRSAEncryption",
	"SHA512WithRSA":   "sha512WithRSAEncryption",
	"ECDSAWithSHA1":   "ecdsa-with-SHA1",
	"ECDSAWithSHA256": "ecdsa-with-SHA256",
	"ECDSAWithSHA384": "ecdsa-with-SHA384",
	"ECDSAWithSHA512": "ecdsa-with-SHA512",
}

var sstls ServerSideTLSJson
var modern, intermediate, old Configuration

var log = logger.GetLogger()

func init() {
	err := json.Unmarshal([]byte(ServerSideTLSConfiguration), &sstls)
	if err != nil {
		log.Error("Could not load Server Side TLS configuration. Evaluation Worker not available")
		return
	}
	modern = sstls.Configurations["modern"]
	intermediate = sstls.Configurations["intermediate"]
	old = sstls.Configurations["old"]
	worker.RegisterWorker(workerName, worker.Info{Runner: new(eval), Description: workerDesc})
}

type ServerSideTLSJson struct {
	Configurations map[string]Configuration `json:"configurations"`
	Version        float64                  `json:"version"`
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
	DHParamSize          float64  `json:"dh_param_size"`
	ECDHParamSize        float64  `json:"ecdh_param_size"`
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

	b, err := Evaluate(in.Connection, in.Certificate.SignatureAlgorithm)
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
func Evaluate(connInfo connection.Stored, certsigalg string) ([]byte, error) {

	var isOldLvl, isInterLvl, isModernLvl, isBadLvl bool

	results := EvaluationResults{}
	results.Failures = make(map[string][]string)

	// assume the worst
	results.Level = "bad"

	isModernLvl, results.Failures["modern"] = isModern(connInfo, certsigalg)
	if isModernLvl {
		results.Level = "modern"

		ord, ordres := isOrdered(connInfo, modern.Ciphers, "modern")
		if !ord {
			ordres = append(ordres, "considering fixing ciphers ordering")
			results.Failures["modern"] = append(results.Failures["modern"], ordres...)
		}
	}

	isInterLvl, results.Failures["intermediate"] = isIntermediate(connInfo, certsigalg)
	if isInterLvl {
		results.Level = "intermediate"

		ord, ordres := isOrdered(connInfo, intermediate.Ciphers, "intermediate")
		if !ord {
			ordres = append(ordres, "considering fixing ciphers ordering")
			results.Failures["intermediate"] = append(results.Failures["intermediate"], ordres...)
		}
	}

	isOldLvl, results.Failures["old"] = isOld(connInfo, certsigalg)
	if isOldLvl {
		results.Level = "old"

		ord, ordres := isOrdered(connInfo, old.Ciphers, "old")
		if !ord {
			ordres = append(ordres, "considering fixing ciphers ordering")
			results.Failures["old"] = append(results.Failures["old"], ordres...)
		}
	}

	isBadLvl, results.Failures["bad"] = isBad(connInfo, certsigalg)
	if isBadLvl {
		results.Level = "bad"
	}

	js, err := json.Marshal(results)
	if err != nil {
		return nil, err
	}

	return js, nil
}

func isBad(c connection.Stored, certsigalg string) (bool, []string) {
	var (
		failures   []string
		allProtos  []string
		allCiphers []string
		isBad      bool = false
		hasSSLv2   bool = false
		hasBadPFS  bool = false
		hasBadPK   bool = false
	)
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
			if !hasGoodPFS(cs.PFS, old.DHParamSize, old.ECDHParamSize, false, false) {
				hasBadPFS = true
			}
		}

		if cs.PubKey < old.RsaKeySize {
			hasBadPK = true
		}

	}

	badCiphers := extra(old.Ciphers, allCiphers)
	if len(badCiphers) > 0 {
		for _, c := range badCiphers {
			failures = append(failures, fmt.Sprintf("remove cipher %s", c))
			isBad = true
		}
	}

	if hasSSLv2 {
		failures = append(failures, "disable SSLv2")
		isBad = true
	}

	if hasBadPFS {
		failures = append(failures,
			fmt.Sprintf("don't use DHE smaller than %.0fbits or ECC smaller than %.0fbits",
				old.DHParamSize, old.ECDHParamSize))
		isBad = true
	}

	if hasBadPK {
		failures = append(failures, fmt.Sprintf("don't use a public key shorter than %dbits", old.RsaKeySize))
		isBad = true
	}

	if certsigalg == "UnknownSignatureAlgorithm" {
		failures = append(failures,
			fmt.Sprintf("certificate signature could not be determined, use a standard algorithm", certsigalg))
		isBad = true
	} else if _, ok := sigAlgTranslation[certsigalg]; !ok {
		failures = append(failures,
			fmt.Sprintf("%s is a bad certificate signature", certsigalg))
		isBad = true
	}

	return isBad, failures
}

func isOld(c connection.Stored, certsigalg string) (bool, []string) {
	var (
		isOld       bool = true
		allProtos   []string
		certsigfail string
		has3DES     bool = false
		hasSSLv3    bool = false
		hasOCSP     bool = true
		hasPFS      bool = true
		failures    []string
	)
	for _, cs := range c.CipherSuite {

		if !contains(old.Ciphers, cs.Cipher) {
			failures = append(failures, fmt.Sprintf("remove cipher %s", cs.Cipher))
			isOld = false
		}

		if cs.Cipher == "DES-CBC3-SHA" {
			has3DES = true
		}

		if !hasSSLv3 && contains(cs.Protocols, "SSLv3") {
			hasSSLv3 = true
		}

		for _, proto := range cs.Protocols {
			if !contains(allProtos, proto) {
				allProtos = append(allProtos, proto)
			}
		}

		if cs.PFS != "None" {
			if !hasGoodPFS(cs.PFS, old.DHParamSize, old.ECDHParamSize, true, false) {
				hasPFS = false
			}
		}

		if !cs.OCSPStapling {
			hasOCSP = false
		}
	}

	if _, ok := sigAlgTranslation[certsigalg]; !ok {
		failures = append(failures,
			fmt.Sprintf("%s is not an old certificate signature, use %s", certsigalg, old.CertificateSignature))
		isOld = false
	} else if sigAlgTranslation[certsigalg] != old.CertificateSignature {
		certsigfail = fmt.Sprintf("%s is not an old certificate signature, use %s", sigAlgTranslation[certsigalg], old.CertificateSignature)
		failures = append(failures, certsigfail)
		isOld = false
	}

	extraProto := extra(old.TLSVersions, allProtos)
	for _, p := range extraProto {
		failures = append(failures, fmt.Sprintf("disable %s protocol", p))
		isOld = false
	}

	missingProto := extra(allProtos, old.TLSVersions)
	for _, p := range missingProto {
		failures = append(failures, fmt.Sprintf("add support for %s", p))
		if p == "SSLv3" {
			isOld = false
		}
	}

	if !c.ServerSide {
		failures = append(failures, "enforce server side ordering")
		isOld = false
	}

	if !hasOCSP {
		failures = append(failures, "consider enabling OCSP stapling")
	}

	if !has3DES {
		failures = append(failures, "add cipher DES-CBC3-SHA")
		isOld = false
	}

	if !hasPFS {
		failures = append(failures,
			fmt.Sprintf("use DHE of %.0fbits and ECC of %.0fbits",
				old.DHParamSize, old.ECDHParamSize))
		isOld = false
	}

	return isOld, failures
}

func isIntermediate(c connection.Stored, certsigalg string) (bool, []string) {
	var (
		isIntermediate bool = true
		allProtos      []string
		hasTLSv1       bool = false
		hasAES         bool = false
		certsigfail    string
		hasOCSP        bool = true
		hasPFS         bool = true
		failures       []string
	)
	for _, cs := range c.CipherSuite {

		if !contains(intermediate.Ciphers, cs.Cipher) {
			failures = append(failures, fmt.Sprintf("remove cipher %s", cs.Cipher))
			isIntermediate = false
		}

		for _, proto := range cs.Protocols {
			if !contains(allProtos, proto) {
				allProtos = append(allProtos, proto)
			}
		}

		if !hasTLSv1 && contains(cs.Protocols, "TLSv1") {
			hasTLSv1 = true
		}

		if cs.Cipher == "AES128-SHA" {
			hasAES = true
		}

		if cs.PFS != "None" {
			if !hasGoodPFS(cs.PFS, intermediate.DHParamSize, intermediate.ECDHParamSize, false, false) {
				hasPFS = false
			}
		}

		if !cs.OCSPStapling {
			hasOCSP = false
		}
	}

	if _, ok := sigAlgTranslation[certsigalg]; !ok {
		certsigfail = fmt.Sprintf("%s is not an intermediate certificate signature, use %s", certsigalg, intermediate.CertificateSignature)
		failures = append(failures, certsigfail)
		isIntermediate = false
	} else if sigAlgTranslation[certsigalg] != intermediate.CertificateSignature {
		certsigfail = fmt.Sprintf("%s is not an intermediate certificate signature, use %s", sigAlgTranslation[certsigalg], intermediate.CertificateSignature)
		failures = append(failures, certsigfail)
		isIntermediate = false
	}

	extraProto := extra(intermediate.TLSVersions, allProtos)
	for _, p := range extraProto {
		failures = append(failures, fmt.Sprintf("disable %s protocol", p))
		isIntermediate = false
	}

	if !hasAES {
		failures = append(failures, "add cipher AES128-SHA")
		isIntermediate = false
	}

	if !hasTLSv1 {
		failures = append(failures, "consider adding TLSv1")
		isIntermediate = false
	}

	if !c.ServerSide {
		failures = append(failures, "enforce server side ordering")
		isIntermediate = false
	}

	if !hasOCSP {
		failures = append(failures, "consider enabling OCSP stapling")
	}

	if !hasPFS {
		failures = append(failures,
			fmt.Sprintf("use DHE of at least %.0fbits and ECC of at least %.0fbits",
				intermediate.DHParamSize, intermediate.ECDHParamSize))
		isIntermediate = false
	}

	return isIntermediate, failures
}

func isModern(c connection.Stored, certsigalg string) (bool, []string) {
	var (
		isModern    bool = true
		allProtos   []string
		certsigfail string
		hasOCSP     bool = true
		hasPFS      bool = true
		failures    []string
	)
	for _, cs := range c.CipherSuite {

		if !contains(modern.Ciphers, cs.Cipher) {
			failures = append(failures, fmt.Sprintf("remove cipher %s", cs.Cipher))
			isModern = false
		}

		for _, proto := range cs.Protocols {
			if !contains(allProtos, proto) {
				allProtos = append(allProtos, proto)
			}
		}

		if cs.PFS != "None" {
			if !hasGoodPFS(cs.PFS, modern.DHParamSize, modern.ECDHParamSize, true, false) {
				hasPFS = false
			}
		}

		if !cs.OCSPStapling {
			hasOCSP = false
		}
	}

	if _, ok := sigAlgTranslation[certsigalg]; !ok {
		certsigfail = fmt.Sprintf("%s is not a modern certificate signature, use %s", certsigalg, modern.CertificateSignature)
		failures = append(failures, certsigfail)
		isModern = false
	} else if sigAlgTranslation[certsigalg] != modern.CertificateSignature {
		certsigfail = fmt.Sprintf("%s is not a modern certificate signature, use %s", sigAlgTranslation[certsigalg], modern.CertificateSignature)
		failures = append(failures, certsigfail)
		isModern = false
	}

	extraProto := extra(modern.TLSVersions, allProtos)
	for _, p := range extraProto {
		failures = append(failures, fmt.Sprintf("disable %s protocol", p))
		isModern = false
	}

	if !c.ServerSide {
		failures = append(failures, "enforce server side ordering")
		isModern = false
	}

	if !hasOCSP {
		failures = append(failures, "consider enabling OCSP stapling")
	}

	if !hasPFS {
		failures = append(failures,
			fmt.Sprintf("enable Perfect Forward Secrecy with a curve of at least %.0fbits, don't use DHE",
				modern.ECDHParamSize))
		isModern = false
	}
	return isModern, failures
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

func hasGoodPFS(curPFS string, targetDH, targetECC float64, mustMatchDH, mustMatchECDH bool) bool {
	pfs := strings.Split(curPFS, ",")
	if len(pfs) < 2 {
		return false
	}

	if "ECDH" == pfs[0] {
		bitsStr := strings.TrimRight(pfs[2], "bits")

		bits, err := strconv.ParseFloat(bitsStr, 64)
		if err != nil {
			return false
		}

		if mustMatchECDH {
			if bits != targetECC {
				return false
			}
		} else {
			if bits < targetECC {
				return false
			}
		}

	} else if "DH" == pfs[0] {
		bitsStr := strings.TrimRight(pfs[1], "bits")

		bits, err := strconv.ParseFloat(bitsStr, 64)
		if err != nil {
			return false
		}

		if mustMatchDH {
			if bits != targetDH {
				return false
			}
		} else {
			if bits < targetDH {
				return false
			}
		}
	} else {
		return false
	}
	return true
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

// extra returns a slice of strings that are present in a source slice
// but not in an expected slice. It is used to detect source entries that
// should be there, using the expected entries.
func extra(source []string, expected []string) (extra []string) {
	for _, expect := range expected {
		if !contains(source, expect) {
			extra = append(extra, expect)
		}
	}
	return
}

func (e eval) PrintAnalysis(r []byte) (results []string, err error) {
	var (
		eval           EvaluationResults
		previousissues []string
		prefix         string
	)
	err = json.Unmarshal(r, &eval)
	if err != nil {
		err = fmt.Errorf("Mozilla evaluation worker: failed to parse results: %v", err)
		return
	}
	results = append(results, fmt.Sprintf("* Mozilla evaluation: %s", eval.Level))
	for _, lvl := range []string{"bad", "old", "intermediate", "modern"} {
		if _, ok := eval.Failures[lvl]; ok && len(eval.Failures[lvl]) > 0 {
			for _, issue := range eval.Failures[lvl] {
				for _, previousissue := range previousissues {
					if issue == previousissue {
						goto next
					}
				}
				prefix = "for " + lvl + " level:"
				if lvl == "bad" {
					prefix = "bad configuration:"
				}
				results = append(results, fmt.Sprintf("  - %s %s", prefix, issue))
				previousissues = append(previousissues, issue)
			next:
			}

		}
	}
	if eval.Level != "bad" {
		results = append(results,
			fmt.Sprintf("  - oldest clients: %s", strings.Join(sstls.Configurations[eval.Level].OldestClients, ", ")))
	}
	return
}
