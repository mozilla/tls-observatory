package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"runtime"
	"time"
	//"strconv"
	//"strings"
	"sync"

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
	"DAS",
	"ECDSA",
}

type StoredCertificate struct {
	Version                float64                  `json:"version"`
	SignatureAlgorithm     string                   `json:"signatureAlgorithm"`
	Issuer                 certIssuer               `json:"issuer"`
	Validity               certValidity             `json:"validity"`
	Subject                certSubject              `json:"subject"`
	SubjectPublicKeyInfo   certSubjectPublicKeyInfo `json:"subjectPublicKeyInfo"`
	X509v3Extensions       certExtensions           `json:"x509v3Extensions"`
	X509v3BasicConstraints string                   `json:"x509v3BasicConstraints"`
	CA                     bool                     `json:"ca"`
	Analysis               interface{}              `json:"analysis"` //for future use...
	ParentSignature        string                   `json:"parentSignature"`
	IsChainValid		   string                   `json:"isChainValid"`//string displays error type along the validation chain...
	CollectionTimestamp    string                   `json:"collectionTimestamp"`
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
	PublicKeyAlgorithm string `json:"publicKeyAlgorithm"`
}

//Currently exporting extensions that are already decoded into the x509 Certificate structure

type certExtensions struct {
	AuthorityKeyId   []byte   `json:"authorityKeyId"`
	SubjectKeyId     []byte   `json:"subjectKeyId"`
	KeyUsage         []string `json:"keyUsage"`
	ExtendedKeyUsage []string `json:"extendedKeyUsage"`
	// Maybe need to create a struct to support Email and IPAddresses as long as DNSNames...
	SubjectAlternativeName []string `json:"subjectAlternativeName"`
	CRLDistributionPoints  []string `json:"crlDistributionPoints"`
}

type CertX509v3BasicConstraints struct {
	CA       bool        `json:"ca"`
	Analysis interface{} `json:"analysis"`
}

type CertChain struct {
	Domain string   `json:"domain"`
	Certs  []string `json:"certs"`
}

type ids struct {
	_type  string   `json:"type"`
	values []string `json:"values"`
}

type JsonRawCert struct{
	RawCert string `json:"rawCert"`
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

func worker(msgs <-chan amqp.Delivery, es *elastigo.Conn) {

	forever := make(chan bool)
	defer wg.Done()

	for d := range msgs {

		chain := CertChain{}

		err := json.Unmarshal(d.Body, &chain)
		panicIf(err)

		log.Println(len(chain.Certs))

		analyseAndPushCertificates(&chain, es)

		// jsonCert, err := json.MarshalIndent(certtoStored(certif), "", "    ")
		// panicIf(err)
		// log.Println(string(jsonCert))
		// _, err = es.Index("certificates", "certificateInfo", SHA256Hash(certif.Raw), nil, jsonCert)
		// _, err = es.Index("certificates", "certificateRaw", SHA256Hash(certif.Raw), nil, base64.StdEncoding.EncodeToString(certif.Raw))
		// panicIf(err)
		d.Ack(false)
	}

	<-forever
}

func analyseAndPushCertificates(chain *CertChain, es *elastigo.Conn) {

	var certs []*x509.Certificate

	for i, data := range chain.Certs {

		certRaw, err := base64.StdEncoding.DecodeString(data)
		panicIf(err)

		var certif *x509.Certificate
		certif, err = x509.ParseCertificate(certRaw)
		panicIf(err)

		if i == 0{ // do this only for the leaf certificate as in most cases intermediate and CA certificate will already be in the DB
			searchJson := `{
		    "query" : {
		        "term" : { "_id" : "` + SHA256Hash(certif.Raw) + `" }
		    }
		}`
			res, e := es.Search("certificates", "certificateInfo", nil, searchJson)
			if !panicIf(e){
				if res.Hits.Total>0{//probably gonna be 0|1
					//certificate is already in the database. Abort??? return
				}
			}
		}

		certs = append(certs, certif)
	}


	inter:= x509.NewCertPool()

	
	for _,c := range certs[1:len(certs)]{
		if c.Issuer.CommonName != ""{

			log.Println("added to Intermediates"+c.Subject.CommonName)
			inter.AddCert(c)
		}
	}

	opts := x509.VerifyOptions{
		DNSName: chain.Domain,
		Intermediates: inter,
	}

	var chains [][]*x509.Certificate

	chains, err := certs[0].Verify(opts)
	

	if len(chains)>0 && !panicIf(err){
		CreateStoredChain(chains[0], "", es)
	}else{
		CreateStoredChain(certs,err.Error(), es)
	}
}

func CreateStoredChain(certs []*x509.Certificate, validation_err string, es *elastigo.Conn){
	for i, cert := range certs{

		searchJson := `{
		    "query" : {
		        "term" : { "_id" : "` + SHA256Hash(cert.Raw) + `" }
		    }
		}`

		res, e := es.Search("certificates", "certificateInfo", nil, searchJson)
		if !panicIf(e){
			if res.Hits.Total>0{//probably gonna be 0|1
				//certificate is already in the database. Abort??? return
			}
		}

		stored := certtoStored(cert)
		jsonCert, err := json.MarshalIndent(stored, "", "    ")
		panicIf(err)

		stored.IsChainValid = validation_err
		if cert.Issuer.CommonName != "" && len(certs)>i+1{
			stored.ParentSignature = SHA256Hash(certs[i+1].Raw)
		}
		_, err = es.Index("certificates", "certificateInfo", SHA256Hash(cert.Raw), nil, jsonCert)
		panicIf(err)

		raw := JsonRawCert{base64.StdEncoding.EncodeToString(cert.Raw)}
		jsonCert, err = json.MarshalIndent(raw, "", "    ")
		panicIf(err)
		_, err = es.Index("certificates", "certificateRaw", SHA256Hash(cert.Raw), nil, jsonCert)
		panicIf(err)
	}
}

//Alternate method of Verifying

// func analyseAndPushCertificates(chain *CertChain){

// 	for i, data := range chain.Certs {

// 		certRaw, err := base64.StdEncoding.DecodeString(data)
// 		panicIf(err)

// 		var certif *x509.Certificate
// 		certif, err = x509.ParseCertificate(certRaw)
// 		panicIf(err)

// 		if i+1<len(chain.Certs){
// 			certRaw, err = base64.StdEncoding.DecodeString(chain.Certs[i+1])
// 			panicIf(err)

// 			var certt *x509.Certificate
// 			certt, err = x509.ParseCertificate(certRaw)
// 			panicIf(err)

// 			log.Println(certif.Subject.CommonName + " - "+ certt.Subject.CommonName )

// 			err = certif.CheckSignatureFrom(certt)
// 			panicIf(err)
// 		}

// 		certs = append(certs, certif)
// 	}

// }

func getExtKeyUsageAsStringArray(cert *x509.Certificate) []string {

	usage := make([]string, len(cert.ExtKeyUsage))

	for _, eku := range cert.ExtKeyUsage {

		usage = append(usage, extKeyUsage[eku])
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

func certtoStored(cert *x509.Certificate) StoredCertificate {

	var stored = StoredCertificate{}

	//Print raw extension info

	// for i, extension := range cert.Extensions{

	// 	var numbers string
	// 	for num ,num2 := range  extension.Id{

	// 		numbers = numbers + " "+ "[" + strconv.Itoa(num)+ " " + strconv.Itoa(num2) + "]"

	// 	}

	// 	log.Println("//",strconv.Itoa(i),": {", numbers,"}",string(extension.Value) )

	// }

	stored.Version = float64(cert.Version)

	stored.SignatureAlgorithm = signatureAlgorithm[cert.SignatureAlgorithm]

	stored.SubjectPublicKeyInfo.PublicKeyAlgorithm = publicKeyAlgorithm[cert.PublicKeyAlgorithm]

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

	if cert.BasicConstraintsValid {

		stored.X509v3BasicConstraints = "Critical"
		stored.CA = cert.IsCA
	} else {
		stored.X509v3BasicConstraints = ""
		stored.CA = false
	}

	stored.CollectionTimestamp = time.Now().UTC().String()
	return stored

}

var wg sync.WaitGroup

func main() {

	conn, err := amqp.Dial("amqp://guest:guest@localhost:5672/")
	failOnError(err, "Failed to connect to RabbitMQ")
	defer conn.Close()

	es := elastigo.NewConn()
	es.Domain = "83.212.99.104:9200"

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

	cores := runtime.NumCPU()
	runtime.GOMAXPROCS(cores)

	for i := 0; i < cores; i++ {
		wg.Add(1)
		go worker(msgs, es)
	}

	wg.Wait()
}
