package main

import (
	// stdlib packages
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"runtime"
	"strconv"
	"sync"
	"time"

	// custom packages
	"config"

	// 3rd party dependencies
	elastigo "github.com/mattbaird/elastigo/lib"
	"github.com/streadway/amqp"
)

var signatureAlgorithm = [...]string{
	"UnknownSignatureAlgorithm",
	"MD2WithRSA",
	"MD5WithRSA",
	"SHA1WithRSA",
	"SHA256WithRSA",
	"SHA384WithRSA",
	"SHA512WithRSA",
	"DSAWithSHA1",
	"DSAWithSHA256",
	"ECDSAWithSHA1",
	"ECDSAWithSHA256",
	"ECDSAWithSHA384",
	"ECDSAWithSHA512",
}

var extKeyUsage = [...]string{
	"ExtKeyUsageAny",
	"ExtKeyUsageServerAuth",
	"ExtKeyUsageClientAuth",
	"ExtKeyUsageCodeSigning",
	"ExtKeyUsageEmailProtection",
	"ExtKeyUsageIPSECEndSystem",
	"ExtKeyUsageIPSECTunnel",
	"ExtKeyUsageIPSECUser",
	"ExtKeyUsageTimeStamping",
	"ExtKeyUsageOCSPSigning",
	"ExtKeyUsageMicrosoftServerGatedCrypto",
	"ExtKeyUsageNetscapeServerGatedCrypto",
}

var publicKeyAlgorithm = [...]string{
	"UnknownPublicKeyAlgorithm",
	"RSA",
	"DSA",
	"ECDSA",
}

type StoredCertificate struct {
	Domains                []string                      `json:"domains,omitempty"`
	IPs                    []string                      `json:"ips,omitempty"`
	Version                float64                       `json:"version"`
	SignatureAlgorithm     string                        `json:"signatureAlgorithm"`
	Issuer                 certIssuer                    `json:"issuer"`
	Validity               certValidity                  `json:"validity"`
	Subject                certSubject                   `json:"subject"`
	SubjectPublicKeyInfo   certSubjectPublicKeyInfo      `json:"subjectPublicKeyInfo"`
	X509v3Extensions       certExtensions                `json:"x509v3Extensions"`
	X509v3BasicConstraints string                        `json:"x509v3BasicConstraints"`
	CA                     bool                          `json:"ca"`
	Analysis               interface{}                   `json:"analysis"` //for future use...
	ParentSignature        []string                      `json:"parentSignature"`
	ValidationInfo         map[string]certValidationInfo `json:"validationInfo"`
	CollectionTimestamp    string                        `json:"collectionTimestamp"`
	LastSeenTimestamp      string                        `json:"lastSeenTimestamp"`
}

type certIssuer struct {
	Country      []string `json:"c"`
	Organisation []string `json:"o"`
	OrgUnit      []string `json:"ou"`
	CommonName   string   `json:"cn"`
}

type certValidity struct {
	NotBefore string `json:"notBefore"`
	NotAfter  string `json:"notAfter"`
}

type certSubject struct {
	Country      []string `json:"c"`
	Organisation []string `json:"o"`
	OrgUnit      []string `json:"ou"`
	CommonName   string   `json:"cn"`
}

type certSubjectPublicKeyInfo struct {
	PublicKeyAlgorithm string  `json:"publicKeyAlgorithm,omitempty"`
	RSAModulusSize     float64 `json:"rsaModulusSize,omitempty"`
	RSAExponent        float64 `json:"rsaExponent,omitempty"`
	DSA_P              string  `json:"DSA_P,omitempty"`
	DSA_Q              string  `json:"DSA_Q,omitempty"`
	DSA_G              string  `json:"DSA_G,omitempty"`
	DSA_Y              string  `json:"DSA_Y,omitempty"`
	ECDSACurveType     string  `json:"ecdsaCurveType,omitempty"`
	ECDSA_X            float64 `json:"ECDSA_X,omitempty"`
	ECDSA_Y            float64 `json:"ECDSA_Y,omitempty"`
}

//Currently exporting extensions that are already decoded into the x509 Certificate structure

type certExtensions struct {
	AuthorityKeyId         []byte   `json:"authorityKeyId"`
	SubjectKeyId           []byte   `json:"subjectKeyId"`
	KeyUsage               []string `json:"keyUsage"`
	ExtendedKeyUsage       []string `json:"extendedKeyUsage"`
	SubjectAlternativeName []string `json:"subjectAlternativeName"`
	CRLDistributionPoints  []string `json:"crlDistributionPoints"`
}

type CertX509v3BasicConstraints struct {
	CA       bool        `json:"ca"`
	Analysis interface{} `json:"analysis"`
}

type CertChain struct {
	Domain string   `json:"domain"`
	IP     string   `json:"ip"`
	Certs  []string `json:"certs"`
}

type ids struct {
	_type  string   `json:"type"`
	values []string `json:"values"`
}

type JsonRawCert struct {
	RawCert string `json:"rawCert"`
}

type TrustStore struct {
	Name  string
	Certs *x509.CertPool
}

type certValidationInfo struct {
	IsValid         bool   `json:"isValid"`
	ValidationError string `json:"validationError"`
	Anomalies       string `json:"anomalies,omitempty"`
}

func failOnError(err error, msg string) {
	if err != nil {
		log.Fatalf("%s: %s", msg, err)
		panic(fmt.Sprintf("%s: %s", msg, err))
	}
}

func SHA256Hash(data []byte) string {
	h := sha256.New()
	h.Write(data)
	return fmt.Sprintf("%X", h.Sum(nil))
	//return hex.EncodeToString(h.Sum(nil))
}

func panicIf(err error) bool {
	if err != nil {
		log.Println(fmt.Sprintf("%s", err))
		return true
	}

	return false
}

func worker(msgs <-chan amqp.Delivery) {

	forever := make(chan bool)
	defer wg.Done()

	for d := range msgs {

		chain := CertChain{}

		err := json.Unmarshal(d.Body, &chain)
		panicIf(err)

		analyseAndPushCertificates(&chain)

		d.Ack(false)
	}

	<-forever
}

func analyseAndPushCertificates(chain *CertChain) {

	var intermediates []*x509.Certificate
	var leafCert *x509.Certificate
	leafCert = nil

	for _, data := range chain.Certs { //create certificate chain from chain struct

		certRaw, err := base64.StdEncoding.DecodeString(data)
		panicIf(err)

		var cert *x509.Certificate
		cert, err = x509.ParseCertificate(certRaw)
		panicIf(err)

		if !cert.IsCA {
			leafCert = cert
		} else {
			intermediates = append(intermediates, cert)
		}
	}

	if leafCert == nil {
		log.Println("No Server certificate found in chain received by:" + chain.Domain)
	}

	//validate against each truststore
	for _, curTS := range trustStores {

		if leafCert != nil {

			if HandleCertChain(leafCert, intermediates, &curTS, chain.Domain, chain.IP) {
				continue
			}
		}

		// to end up here either there was no leaf certificate retrieved
		// or it was retrieved but it was not valid so we must check the remainder of the chain
		for i, cert := range intermediates {

			inter := append(intermediates[:i], intermediates[i+1:]...)

			HandleCertChain(cert, inter, &curTS, chain.Domain, chain.IP)
			//should we break if/when this validates?
		}

	}
}

func HandleCertChain(certificate *x509.Certificate, intermediates []*x509.Certificate, curTS *TrustStore, domain, IP string) bool {

	valInfo := &certValidationInfo{}

	valInfo.IsValid = true

	inter := x509.NewCertPool()
	for _, in := range intermediates {
		inter.AddCert(in)
	}

	dnsName := domain

	if certificate.IsCA {
		dnsName = certificate.Subject.CommonName
	}

	opts := x509.VerifyOptions{
		DNSName:       dnsName,
		Intermediates: inter,
		Roots:         curTS.Certs,
	}

	chains, err := certificate.Verify(opts)

	if err == nil {

		for i, ch := range chains {
			log.Println("Trust chain no:", strconv.Itoa(i), "length: ", len(ch))
			for _, cert := range ch {

				parentSignature := ""
				c := getFirstParent(cert, ch)

				if c != nil {
					parentSignature = SHA256Hash(c.Raw)
				} else {
					log.Println("could not retrieve parent for " + dnsName)
				}

				pushCertificate(cert, parentSignature, domain, IP, curTS.Name, valInfo)
			}
		}
		return true
	} else {
		if len(chains) > 0 {
			log.Println("validation error but validation chain populated for: " + dnsName)
		}

		valInfo.ValidationError = err.Error()
		valInfo.IsValid = false

		parentSignature := ""
		c := getFirstParent(certificate, intermediates)

		if c != nil {
			parentSignature = SHA256Hash(c.Raw)
		} else {
			log.Println("could not retrieve parent for " + dnsName)
		}

		pushCertificate(certificate, parentSignature, domain, IP, curTS.Name, valInfo)

		return false
	}

}

//Returns the first parent found for a certificate in a given certificate list ( does not verify signature)
func getFirstParent(cert *x509.Certificate, certs []*x509.Certificate) *x509.Certificate {
	for _, c := range certs {
		if cert.Issuer.CommonName == c.Subject.CommonName { //TODO : consider changing this check with validating check
			return c
		}
	}
	//parent not found
	return nil
}

func pushCertificate(cert *x509.Certificate, parentSignature string, domain, ip, TSName string, valInfo *certValidationInfo) {

	searchJson := `{
	    "query" : {
	        "term" : { "_id" : "` + SHA256Hash(cert.Raw) + `" }
	    }
	}`
	res, e := es.Search("certificates", "certificateInfo", nil, searchJson)
	panicIf(e)
	if res.Hits.Total > 0 { //Is certificate alreadycollected?

		storedCert := StoredCertificate{}

		err := json.Unmarshal(*res.Hits.Hits[0].Source, &storedCert)
		panicIf(err)

		t := time.Now().UTC()

		storedCert.LastSeenTimestamp = fmt.Sprintf("%d-%02d-%02dT%02d:%02d:%02d", t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second())

		parentFound := false

		for _, p := range storedCert.ParentSignature {

			if parentSignature == p {
				parentFound = true
				break
			}
		}

		if !parentFound {
			storedCert.ParentSignature = append(storedCert.ParentSignature, parentSignature)
		}

		if !storedCert.CA {

			domainFound := false

			for _, d := range storedCert.Domains {
				if domain == d {
					domainFound = true
					break
				}
			}

			if !domainFound {
				storedCert.Domains = append(storedCert.Domains, domain)
			}

			ipFound := false

			for _, i := range storedCert.IPs {
				if ip == i {
					ipFound = true
					break
				}
			}

			if !ipFound {
				storedCert.IPs = append(storedCert.IPs, ip)
			}
		}

		storedCert.ValidationInfo[TSName] = *valInfo

		jsonCert, err := json.Marshal(storedCert)
		panicIf(err)

		_, err = es.Index("certificates", "certificateInfo", SHA256Hash(cert.Raw), nil, jsonCert)
		panicIf(err)
		log.Println("Updated cert id", SHA256Hash(cert.Raw), "subject cn", cert.Subject.CommonName)
	} else {

		stored := certtoStored(cert, parentSignature, domain, ip, TSName, valInfo)
		jsonCert, err := json.Marshal(stored)
		panicIf(err)

		_, err = es.Index("certificates", "certificateInfo", SHA256Hash(cert.Raw), nil, jsonCert)
		panicIf(err)

		raw := JsonRawCert{base64.StdEncoding.EncodeToString(cert.Raw)}
		jsonCert, err = json.Marshal(raw)
		panicIf(err)
		_, err = es.Index("certificates", "certificateRaw", SHA256Hash(cert.Raw), nil, jsonCert)
		panicIf(err)
		log.Println("Stored cert id", SHA256Hash(cert.Raw), "subject cn", cert.Subject.CommonName)
	}

}

func getExtKeyUsageAsStringArray(cert *x509.Certificate) []string {

	usage := make([]string, len(cert.ExtKeyUsage))

	for i, eku := range cert.ExtKeyUsage {

		usage[i] = extKeyUsage[eku]
	}

	return usage
}

func getKeyUsageAsStringArray(cert *x509.Certificate) []string {

	var usage []string
	keyUsage := cert.KeyUsage

	//calculate included keyUsage from bitmap
	//String values taken from OpenSSL

	if keyUsage&x509.KeyUsageDigitalSignature != 0 {
		usage = append(usage, "Digital Signature")
	}
	if keyUsage&x509.KeyUsageContentCommitment != 0 {
		usage = append(usage, "Non Repudiation")
	}

	if keyUsage&x509.KeyUsageKeyEncipherment != 0 {
		usage = append(usage, "Key Encipherment")
	}

	if keyUsage&x509.KeyUsageDataEncipherment != 0 {
		usage = append(usage, "Data Encipherment")
	}

	if keyUsage&x509.KeyUsageKeyAgreement != 0 {
		usage = append(usage, "Key Agreement")
	}

	if keyUsage&x509.KeyUsageCertSign != 0 {
		usage = append(usage, "Certificate Sign")
	}

	if keyUsage&x509.KeyUsageCRLSign != 0 {
		usage = append(usage, "CRL Sign")
	}

	if keyUsage&x509.KeyUsageEncipherOnly != 0 {
		usage = append(usage, "Encipher Only")
	}

	if keyUsage&x509.KeyUsageDecipherOnly != 0 {
		usage = append(usage, "Decipher Only")
	}

	return usage
}

//This function currently stores only the extensions that are already exported by GoLang
//(in the x509 Certificate Struct)
func getCertExtensions(cert *x509.Certificate) certExtensions {

	extensions := certExtensions{}

	extensions.AuthorityKeyId = []byte(base64.StdEncoding.EncodeToString(cert.AuthorityKeyId))
	extensions.SubjectKeyId = []byte(base64.StdEncoding.EncodeToString(cert.SubjectKeyId))

	extensions.KeyUsage = getKeyUsageAsStringArray(cert)

	extensions.ExtendedKeyUsage = getExtKeyUsageAsStringArray(cert)

	extensions.SubjectAlternativeName = cert.DNSNames

	extensions.CRLDistributionPoints = cert.CRLDistributionPoints

	return extensions

}

func getPublicKeyInfo(cert *x509.Certificate) certSubjectPublicKeyInfo {

	var pubInfo = certSubjectPublicKeyInfo{}

	pubInfo.PublicKeyAlgorithm = publicKeyAlgorithm[cert.PublicKeyAlgorithm]

	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		pubInfo.RSAModulusSize = float64(pub.N.BitLen())
		pubInfo.RSAExponent = float64(pub.E)

	case *dsa.PublicKey:
		textInt, err := pub.G.MarshalText()

		if err == nil {
			pubInfo.DSA_G = string(textInt)
		} else {
			panicIf(err)
		}

		textInt, err = pub.P.MarshalText()

		if err == nil {
			pubInfo.DSA_P = string(textInt)
		} else {
			panicIf(err)
		}

		textInt, err = pub.Q.MarshalText()

		if err == nil {
			pubInfo.DSA_Q = string(textInt)
		} else {
			panicIf(err)
		}

		textInt, err = pub.Y.MarshalText()

		if err == nil {
			pubInfo.DSA_Y = string(textInt)
		} else {
			panicIf(err)
		}

	case *ecdsa.PublicKey:

		pubInfo.ECDSACurveType = strconv.Itoa(pub.Curve.Params().BitSize)
		pubInfo.ECDSA_Y = float64(pub.Y.BitLen())
		pubInfo.ECDSA_X = float64(pub.X.BitLen())
	}

	return pubInfo

}

func certtoStored(cert *x509.Certificate, parentSignature, domain, ip string, TSName string, valInfo *certValidationInfo) StoredCertificate {

	var stored = StoredCertificate{}

	stored.Version = float64(cert.Version)

	stored.SignatureAlgorithm = signatureAlgorithm[cert.SignatureAlgorithm]

	stored.SubjectPublicKeyInfo = getPublicKeyInfo(cert)

	stored.Issuer.Country = cert.Issuer.Country
	stored.Issuer.Organisation = cert.Issuer.Organization
	stored.Issuer.OrgUnit = cert.Issuer.OrganizationalUnit
	stored.Issuer.CommonName = cert.Issuer.CommonName

	stored.Subject.Country = cert.Subject.Country
	stored.Subject.Organisation = cert.Subject.Organization
	stored.Subject.OrgUnit = cert.Subject.OrganizationalUnit
	stored.Subject.CommonName = cert.Subject.CommonName

	stored.Validity.NotBefore = cert.NotBefore.UTC().String()
	stored.Validity.NotAfter = cert.NotAfter.UTC().String()

	stored.X509v3Extensions = getCertExtensions(cert)

	//below check tries to hack around the basic constraints extension
	//not being available in versions < 3.
	//Only the IsCa variable is set, as setting X509v3BasicConstraints
	//messes up the validation procedure.
	if cert.Version < 3 {

		stored.CA = cert.IsCA

	} else {
		if cert.BasicConstraintsValid {

			stored.X509v3BasicConstraints = "Critical"
			stored.CA = cert.IsCA
		} else {
			stored.X509v3BasicConstraints = ""
			stored.CA = false
		}
	}

	t := time.Now().UTC()

	stored.CollectionTimestamp = fmt.Sprintf("%d-%02d-%02dT%02d:%02d:%02d", t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second())
	stored.LastSeenTimestamp = fmt.Sprintf("%d-%02d-%02dT%02d:%02d:%02d", t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second())

	stored.ParentSignature = append(stored.ParentSignature, parentSignature)

	if !cert.IsCA {
		stored.Domains = append(stored.Domains, domain)
		stored.IPs = append(stored.IPs, ip)
	}

	stored.ValidationInfo = make(map[string]certValidationInfo)
	stored.ValidationInfo[TSName] = *valInfo

	return stored

}

//Print raw extension info
//for debugging purposes
func printRawCertExtensions(cert *x509.Certificate) {

	for i, extension := range cert.Extensions {

		var numbers string
		for num, num2 := range extension.Id {

			numbers = numbers + " " + "[" + strconv.Itoa(num) + " " + strconv.Itoa(num2) + "]"

		}
		log.Println("//", strconv.Itoa(i), ": {", numbers, "}", string(extension.Value))
	}

}

func printIntro() {
	fmt.Println(`
	##################################
	#         CertAnalyzer           #
	##################################
	`)
}

var wg sync.WaitGroup
var trustStores []TrustStore
var es *elastigo.Conn

func main() {
	var (
		err error
	)
	cores := runtime.NumCPU()
	runtime.GOMAXPROCS(cores * 2)

	printIntro()

	conf := config.AnalyzerConfig{}

	var cfgFile string
	flag.StringVar(&cfgFile, "c", "/etc/observer/analyzer.cfg", "Input file csv format")
	flag.Parse()

	_, err = os.Stat(cfgFile)
	failOnError(err, "Missing configuration file from '-c' or /etc/observer/retriever.cfg")

	conf, err = config.AnalyzerConfigLoad(cfgFile)
	if err != nil {
		conf = config.GetAnalyzerDefaults()
	}

	conn, err := amqp.Dial(conf.General.RabbitMQRelay)
	failOnError(err, "Failed to connect to RabbitMQ")
	defer conn.Close()

	es = elastigo.NewConn()
	es.Domain = conf.General.ElasticSearch

	ch, err := conn.Channel()
	failOnError(err, "Failed to open a channel")
	defer ch.Close()

	q, err := ch.QueueDeclare(
		"scan_results_queue", // name
		true,                 // durable
		false,                // delete when unused
		false,                // exclusive
		false,                // no-wait
		nil,                  // arguments
	)
	failOnError(err, "Failed to declare a queue")

	err = ch.Qos(
		3,     // prefetch count
		0,     // prefetch size
		false, // global
	)

	failOnError(err, "Failed to set QoS")

	msgs, err := ch.Consume(
		q.Name, // queue
		"",     // consumer
		false,  // auto-ack
		false,  // exclusive
		false,  // no-local
		false,  // no-wait
		nil,    // args
	)

	failOnError(err, "Failed to register a consumer")

	//Register truststores
	for i, name := range conf.TrustStores.Name {

		poolData, e := ioutil.ReadFile(conf.TrustStores.Path[i])

		if panicIf(e) {
			continue
		}

		certPool := x509.NewCertPool()

		for len(poolData) > 0 {

			var block *pem.Block
			block, poolData = pem.Decode(poolData)
			if block == nil {
				break
			}
			if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
				continue
			}

			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {

				log.Println("Could not parse current certificate from :" + name)
				continue
			}

			if cert.Version < 3 { //solution for older x509 certificate versions that do not have a CA part
				cert.IsCA = true
			}

			certPool.AddCert(cert)
		}

		trustStores = append(trustStores, TrustStore{name, certPool})

	}

	if len(trustStores) == 0 {
		defaultName := "default-" + runtime.GOOS
		// nil Root certPool will result in the system defaults being loaded
		trustStores = append(trustStores, TrustStore{defaultName, nil})
	}

	for i := 0; i < cores; i++ {
		wg.Add(1)
		go worker(msgs)
	}

	wg.Wait()
}
