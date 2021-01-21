package mozillaEvaluationWorker

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/mozilla/tls-observatory/certificate"
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

var sstlsURL = "https://statics.tls.security.mozilla.org/server-side-tls-conf.json"

var sstls ServerSideTLSJson
var modern, intermediate, old Configuration

var once sync.Once

var log = logger.GetLogger()

func init() {
	runner := new(eval)
	worker.RegisterPrinter(workerName, worker.Info{Runner: runner, Description: workerDesc})
	worker.RegisterWorker(workerName, worker.Info{Runner: runner, Description: workerDesc})
}

func loadConfigurations() {
	err := getConffromURL(sstlsURL)
	if err != nil {
		log.Warn(err)
		log.Warn("Could not get tls confs from url - fallback to locally saved configurations")
		// Try to continue with the locally hosted TLS configurations
		err = json.Unmarshal([]byte(ServerSideTLSConfiguration), &sstls)
		if err != nil {
			log.Error(err)
			panic("Could not load Server Side TLS configuration. Evaluation Worker not available")
		}
	}
	modern = sstls.Configurations["modern"]
	intermediate = sstls.Configurations["intermediate"]
	old = sstls.Configurations["old"]
}

// getConffromURL retrieves the json containing the TLS configurations from the specified URL.
func getConffromURL(url string) error {

	r, err := http.Get(url)
	if err != nil {
		return err
	}
	defer r.Body.Close()

	err = json.NewDecoder(r.Body).Decode(&sstls)
	if err != nil {
		return err
	}

	return nil
}

// ServerSideTLSJson contains all the available configurations and the version of the current document.
type ServerSideTLSJson struct {
	Configurations map[string]Configuration `json:"configurations"`
	Version        float64                  `json:"version"`
}

// Configuration represents configurations levels declared by the Mozilla server-side-tls
// see https://wiki.mozilla.org/Security/Server_Side_TLS
type Configuration struct {
	OpenSSLCiphersuites   string   `json:"openssl_ciphersuites"`
	Ciphersuites          []string `json:"ciphersuites"`
	TLSVersions           []string `json:"tls_versions"`
	TLSCurves             []string `json:"tls_curves"`
	CertificateTypes      []string `json:"certificate_types"`
	CertificateCurves     []string `json:"certificate_curves"`
	CertificateSignatures []string `json:"certificate_signatures"`
	RsaKeySize            float64  `json:"rsa_key_size"`
	DHParamSize           float64  `json:"dh_param_size"`
	ECDHParamSize         float64  `json:"ecdh_param_size"`
	HstsMinAge            float64  `json:"hsts_min_age"`
	OldestClients         []string `json:"oldest_clients"`
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

	once.Do(loadConfigurations)
	res := worker.Result{WorkerName: workerName}

	b, err := Evaluate(in.Connection, in.Certificate)
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
func Evaluate(connInfo connection.Stored, cert certificate.Certificate) ([]byte, error) {

	var isOldLvl, isInterLvl, isModernLvl, isBadLvl bool

	results := EvaluationResults{}
	results.Failures = make(map[string][]string)

	// assume non-compliance
	results.Level = "non compliant"

	isOldLvl, results.Failures["old"] = isOld(connInfo, cert)
	if isOldLvl {
		results.Level = "old"

		ord, ordres := isOrdered(connInfo, old.Ciphersuites, "old")
		if !ord {
			results.Failures["old"] = append(results.Failures["old"], ordres...)
		}
	}

	isInterLvl, results.Failures["intermediate"] = isIntermediate(connInfo, cert)
	if isInterLvl {
		results.Level = "intermediate"

		ord, ordres := isOrdered(connInfo, intermediate.Ciphersuites, "intermediate")
		if !ord {
			results.Failures["intermediate"] = append(results.Failures["intermediate"], ordres...)
		}
	}

	isModernLvl, results.Failures["modern"] = isModern(connInfo, cert)
	if isModernLvl {
		results.Level = "modern"

		ord, ordres := isOrdered(connInfo, modern.Ciphersuites, "modern")
		if !ord {
			results.Failures["modern"] = append(results.Failures["modern"], ordres...)
		}
	}

	isBadLvl, results.Failures["bad"] = isBad(connInfo, cert)
	if isBadLvl {
		results.Level = "bad"
	}

	js, err := json.Marshal(results)
	if err != nil {
		return nil, err
	}

	return js, nil
}

func isBad(c connection.Stored, cert certificate.Certificate) (bool, []string) {
	var (
		failures   []string
		allProtos  []string
		allCiphers []string
		isBad      bool = false
		hasSSLv2   bool = false
		hasBadPFS  bool = false
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
	}

	badCiphers := extra(old.Ciphersuites, allCiphers)
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

	if cert.SignatureAlgorithm == "UnknownSignatureAlgorithm" {
		failures = append(failures,
			fmt.Sprintf("certificate signature could not be determined, use a standard algorithm, got %v", cert.SignatureAlgorithm))
		isBad = true
	} else if _, ok := sigAlgTranslation[cert.SignatureAlgorithm]; !ok {
		failures = append(failures,
			fmt.Sprintf("%s is a bad certificate signature", cert.SignatureAlgorithm))
		isBad = true
	}

	if (cert.Key.Alg == "RSA" && cert.Key.Size < 2048) || (cert.Key.Alg == "ECDSA" && cert.Key.Size < 256) {
		failures = append(failures, "don't use a key smaller than 2048bits (RSA) or 256bits (ECDSA)")
		isBad = true
	}
	return isBad, failures
}

func isOld(c connection.Stored, cert certificate.Certificate) (bool, []string) {
	var (
		isOld       bool = true
		allProtos   []string
		allCiphers  []string
		certsigfail string
		has3DES     bool = false
		hasSSLv3    bool = false
		hasCertType bool = false
		hasOCSP     bool = true
		hasPFS      bool = true
		failures    []string
	)
	for _, cs := range c.CipherSuite {
		allCiphers = append(allCiphers, cs.Cipher)

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

	if _, ok := sigAlgTranslation[cert.SignatureAlgorithm]; !ok {
		failures = append(failures,
			fmt.Sprintf("%s is not an old certificate signature, use %s",
				cert.SignatureAlgorithm, strings.Join(old.CertificateSignatures, " or ")))
		isOld = false
	} else if !contains(old.CertificateSignatures, sigAlgTranslation[cert.SignatureAlgorithm]) {
		certsigfail = fmt.Sprintf("%s is not an old certificate signature, use %s",
			sigAlgTranslation[cert.SignatureAlgorithm], strings.Join(old.CertificateSignatures, " or "))
		failures = append(failures, certsigfail)
		isOld = false
	}

	extraCiphers := extra(old.Ciphersuites, allCiphers)
	if len(extraCiphers) > 0 {
		failures = append(failures, fmt.Sprintf("remove ciphersuites %s", strings.Join(extraCiphers, ", ")))
		isOld = false
	}

	missingCiphers := extra(allCiphers, old.Ciphersuites)
	if len(missingCiphers) > 0 {
		failures = append(failures, fmt.Sprintf("consider adding ciphers %s", strings.Join(missingCiphers, ", ")))
	}

	extraProto := extra(old.TLSVersions, allProtos)
	if len(extraProto) > 0 {
		failures = append(failures, fmt.Sprintf("remove protocols %s", strings.Join(extraProto, ", ")))
		isOld = false
	}

	missingProto := extra(allProtos, old.TLSVersions)
	if len(missingProto) > 0 {
		failures = append(failures, fmt.Sprintf("add protocols %s", strings.Join(missingProto, ", ")))
		if !contains(missingProto, "SSLv3") {
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
		failures = append(failures, "add cipher DES-CBC3-SHA for backward compatibility")
		isOld = false
	}

	if !hasPFS {
		failures = append(failures,
			fmt.Sprintf("use DHE of %.0fbits and ECC of %.0fbits",
				old.DHParamSize, old.ECDHParamSize))
		isOld = false
	}

	for _, ct := range old.CertificateTypes {
		if strings.ToUpper(cert.Key.Alg) == strings.ToUpper(ct) {
			hasCertType = true
		}
	}
	if !hasCertType {
		failures = append(failures,
			fmt.Sprintf("use a certificate of the type %s, not %s",
				strings.Join(old.CertificateTypes, ", "), cert.Key.Alg))
		isOld = false
	}

	if cert.Key.Alg == "RSA" && cert.Key.Size != old.RsaKeySize {
		failures = append(failures,
			fmt.Sprintf("use a key size of %.0fbits", old.RsaKeySize))
		isOld = false

	}

	return isOld, failures
}

func isIntermediate(c connection.Stored, cert certificate.Certificate) (bool, []string) {
	var (
		isIntermediate bool = true
		allProtos      []string
		allCiphers     []string
		certsigfail    string
		hasCertType    bool = false
		hasOCSP        bool = true
		hasPFS         bool = true
		failures       []string
	)
	for _, cs := range c.CipherSuite {
		allCiphers = append(allCiphers, cs.Cipher)

		for _, proto := range cs.Protocols {
			if !contains(allProtos, proto) {
				allProtos = append(allProtos, proto)
			}
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

	if _, ok := sigAlgTranslation[cert.SignatureAlgorithm]; !ok {
		certsigfail = fmt.Sprintf("%s is not an intermediate certificate signature, use %s",
			cert.SignatureAlgorithm, strings.Join(intermediate.CertificateSignatures, " or "))
		failures = append(failures, certsigfail)
		isIntermediate = false
	} else if !contains(intermediate.CertificateSignatures, sigAlgTranslation[cert.SignatureAlgorithm]) {
		certsigfail = fmt.Sprintf("%s is not an intermediate certificate signature, use %s",
			sigAlgTranslation[cert.SignatureAlgorithm], strings.Join(intermediate.CertificateSignatures, " or "))
		failures = append(failures, certsigfail)
		isIntermediate = false
	}

	extraCiphers := extra(intermediate.Ciphersuites, allCiphers)
	if len(extraCiphers) > 0 {
		failures = append(failures, fmt.Sprintf("remove ciphersuites %s", strings.Join(extraCiphers, ", ")))
		isIntermediate = false
	}

	missingCiphers := extra(allCiphers, intermediate.Ciphersuites)
	if len(missingCiphers) > 0 {
		failures = append(failures, fmt.Sprintf("consider adding ciphers %s", strings.Join(missingCiphers, ", ")))
	}

	extraProto := extra(intermediate.TLSVersions, allProtos)
	if len(extraProto) > 0 {
		failures = append(failures, fmt.Sprintf("remove protocols %s", strings.Join(extraProto, ", ")))
		isIntermediate = false
	}

	missingProto := extra(allProtos, intermediate.TLSVersions)
	if len(missingProto) > 0 {
		failures = append(failures, fmt.Sprintf("add protocols %s", strings.Join(missingProto, ", ")))
		if !contains(missingProto, "TLSv1") {
			isIntermediate = false
		}
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

	for _, ct := range intermediate.CertificateTypes {
		if strings.ToUpper(cert.Key.Alg) == strings.ToUpper(ct) {
			hasCertType = true
		}
	}
	if !hasCertType {
		failures = append(failures,
			fmt.Sprintf("use a certificate of type %s, not %s",
				strings.Join(intermediate.CertificateTypes, ", "), cert.Key.Alg))
		isIntermediate = false
	}

	switch cert.Key.Alg {
	case "RSA":
		if cert.Key.Size < intermediate.RsaKeySize {
			failures = append(failures,
				fmt.Sprintf("use a key size of at least %.0fbits", intermediate.RsaKeySize))
			isIntermediate = false
		}
	case "ECDSA":
		if cert.Key.Size < intermediate.ECDHParamSize {
			failures = append(failures,
				fmt.Sprintf("use a key size of at least %.0fbits", intermediate.ECDHParamSize))
			isIntermediate = false
		}
	}

	return isIntermediate, failures
}

func isModern(c connection.Stored, cert certificate.Certificate) (bool, []string) {
	var (
		isModern    bool = true
		allProtos   []string
		allCiphers  []string
		certsigfail string
		hasCertType bool = false
		hasOCSP     bool = true
		hasPFS      bool = true
		failures    []string
	)
	for _, cs := range c.CipherSuite {
		allCiphers = append(allCiphers, cs.Cipher)

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

	if _, ok := sigAlgTranslation[cert.SignatureAlgorithm]; !ok {
		certsigfail = fmt.Sprintf("%s is not a modern certificate signature, use %s",
			cert.SignatureAlgorithm, strings.Join(modern.CertificateSignatures, " or "))
		failures = append(failures, certsigfail)
		isModern = false
	} else if !contains(modern.CertificateSignatures, sigAlgTranslation[cert.SignatureAlgorithm]) {
		certsigfail = fmt.Sprintf("%s is not a modern certificate signature, use %s",
			sigAlgTranslation[cert.SignatureAlgorithm], strings.Join(modern.CertificateSignatures, " or "))
		failures = append(failures, certsigfail)
		isModern = false
	}

	extraCiphers := extra(modern.Ciphersuites, allCiphers)
	if len(extraCiphers) > 0 {
		failures = append(failures, fmt.Sprintf("remove ciphersuites %s", strings.Join(extraCiphers, ", ")))
		isModern = false
	}

	missingCiphers := extra(allCiphers, modern.Ciphersuites)
	if len(missingCiphers) > 0 {
		failures = append(failures, fmt.Sprintf("consider adding ciphers %s", strings.Join(missingCiphers, ", ")))
	}

	extraProto := extra(modern.TLSVersions, allProtos)
	if len(extraProto) > 0 {
		failures = append(failures, fmt.Sprintf("remove protocols %s", strings.Join(extraProto, ", ")))
		isModern = false
	}

	missingProto := extra(allProtos, modern.TLSVersions)
	if len(missingProto) > 0 {
		failures = append(failures, fmt.Sprintf("add protocols %s", strings.Join(missingProto, ", ")))
		if !contains(missingProto, "TLSv1.2") {
			isModern = false
		}
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
	for _, ct := range modern.CertificateTypes {
		if strings.ToUpper(cert.Key.Alg) == strings.ToUpper(ct) {
			hasCertType = true
		}
	}
	if !hasCertType {
		failures = append(failures,
			fmt.Sprintf("use a certificate of type %s, not %s",
				strings.Join(modern.CertificateTypes, ", "), cert.Key.Alg))
		isModern = false
	}

	if cert.Key.Alg == "ECDSA" && cert.Key.Size < modern.ECDHParamSize {
		failures = append(failures,
			fmt.Sprintf("use a key size of at least %.0fbits", modern.ECDHParamSize))
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

// extra returns a slice of strings that are present in a slice s1 but not
// in a slice s2.
func extra(s1, s2 []string) (extra []string) {
	for _, e := range s2 {
		// FIXME: https://github.com/mozilla/tls-observatory/issues/186
		if e == "ECDHE-ECDSA-CHACHA20-POLY1305-OLD" || e == "ECDHE-RSA-CHACHA20-POLY1305-OLD" {
			continue
		}
		if !contains(s1, e) {
			extra = append(extra, e)
		}
	}
	return
}

func (e eval) AnalysisPrinter(r []byte, targetLevel interface{}) (results []string, err error) {
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
	levels := []string{"bad", "old", "intermediate", "modern"}
	if targetLevel == nil || targetLevel.(string) == "" {
		levels = []string{"bad", "modern"}
	} else {
		switch targetLevel.(string) {
		case "old", "intermediate", "modern":
			levels = []string{"bad", targetLevel.(string)}
		default:
			err = fmt.Errorf("Invalid target level %q. Must be old, intermediate or modern.", targetLevel.(string))
			return
		}
	}
	for _, lvl := range levels {
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
	if targetLevel.(string) != "" && eval.Level != targetLevel.(string) {
		err = fmt.Errorf("  - measured level is %q and does not match target level %q",
			eval.Level, targetLevel.(string))
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
	if evres.Level != assertres.Level {
		body = []byte(fmt.Sprintf(`Assertion mozillaEvaluationWorker.level=%q failed because measured level is %q`,
			assertres.Level, evres.Level))
		pass = false
	} else {
		pass = true
	}
	return
}
