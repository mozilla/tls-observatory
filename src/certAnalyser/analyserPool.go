package main

import (
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"runtime"
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

var keyUsage = [...]string{
	"KeyUsageDigitalSignature",
	"KeyUsageContentCommitment",
	"KeyUsageKeyEncipherment",
	"KeyUsageDataEncipherment",
	"KeyUsageKeyAgreement",
	"KeyUsageCertSign",
	"KeyUsageCRLSign",
	"KeyUsageEncipherOnly",
	"KeyUsageDecipherOnly",
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
	X509v3Extensions       [][]string               `json:"x509v3Extensions"`
	X509v3ExtendedKeyUsage [][]string               `json:"x509v3ExtendedKeyUsage"`
	X509v3BasicConstraints string                   `json:"x509v3BasicConstraints"`
	CA                     bool                     `json:"ca"`
	Analysis               interface{}              `json:"analysis"`
}

type certIssuer struct {
	Country      string `json:"c"`
	Organisation string `json:"o"`
	OrgUnit      string `json:"ou"`
	CommonName   string `json:"cn"`
}

type certValidity struct {
	NotBefore string `json:"notBefore"`
	NotAfter  string `json:"notAfter"`
}

type certSubject struct {
	Country          string `json:"c"`
	Organisation     string `json:"o"`
	OrgUnit          string `json:"ou"`
	CommonName       string `json:"cn"`
	BusinessCategory string `json:"businessCategory"`
}

type certSubjectPublicKeyInfo struct {
	PublicKeyAlgorithm string `json:"publicKeyAlgorithm"`
}

type CertX509v3BasicConstraints struct {
	CA       bool        `json:"ca"`
	Analysis interface{} `json:"analysis"`
}

func failOnError(err error, msg string) {
	if err != nil {
		log.Fatalf("%s: %s", msg, err)
		panic(fmt.Sprintf("%s: %s", msg, err))
	}
}

func SHA1Hash(data []byte) string {
	h := sha1.New()
	h.Write(data)
	return fmt.Sprintf("%X", h.Sum(nil))
}

func panicIf(err error) {
	if err != nil {
		panic(fmt.Sprintf("%s", err))
	}
}

func worker(msgs <-chan amqp.Delivery, es *elastigo.Conn) {

	forever := make(chan bool)
	defer wg.Done()

	for d := range msgs {
		var certif *x509.Certificate
		data, err := base64.StdEncoding.DecodeString(string(d.Body))
		panicIf(err)
		certif, err = x509.ParseCertificate(data)
		panicIf(err)

		jsonCert, err := json.MarshalIndent(certtoStored(certif), "", "    ")
		// Index a doc using Structs
		_, err = es.Index("certificates", "certificate", SHA1Hash(certif.Raw), nil, jsonCert)
		panicIf(err)
		d.Ack(false)
	}

	<-forever
}

func certtoStored(cert *x509.Certificate) StoredCertificate {

	var stored = StoredCertificate{}

	stored.Version = float64(cert.Version)
	stored.SignatureAlgorithm = signatureAlgorithm[cert.SignatureAlgorithm]
	stored.SubjectPublicKeyInfo.PublicKeyAlgorithm = publicKeyAlgorithm[cert.PublicKeyAlgorithm]
	// stored.Issuer.Country = cert.Issuer.Country
	// stored.Issuer.Organistion = cert.Issuer.Organisation
	// stored.Issuer.OrgUnit = cert.Issuer.OrganizationalUnit
	stored.Issuer.CommonName = cert.Issuer.CommonName
	stored.Validity.NotBefore = cert.NotBefore.Local().String()
	stored.Validity.NotAfter = cert.NotAfter.Local().String()
	stored.Subject.CommonName = cert.Subject.CommonName

	return stored

}

var wg sync.WaitGroup

func main() {

	conn, err := amqp.Dial("amqp://guest:guest@localhost:5672/")
	failOnError(err, "Failed to connect to RabbitMQ")
	defer conn.Close()

	es := elastigo.NewConn()
	es.Domain = "localhost:9200"

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
