package main

import (
	"crypto/sha1"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"time"
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

var publicKeyAlgorithm = [...]string{
	"UnknownPublicKeyAlgorithm",
	"RSA",
	"DAS",
	"ECDSA",
}

var programName = "tlsRetriever"

func ExpiresIn(t time.Time) string {
	units := [...]struct {
		suffix string
		unit   time.Duration
	}{
		{"days", 24 * time.Hour},
		{"hours", time.Hour},
		{"minutes", time.Minute},
		{"seconds", time.Second},
	}
	d := t.Sub(time.Now())
	for _, u := range units {
		if d > u.unit {
			return fmt.Sprintf("Expires in %d %s", d/u.unit, u.suffix)
		}
	}
	return fmt.Sprintf("Expired on %s", t.Local())
}

func SHA1Hash(data []byte) string {
	h := sha1.New()
	h.Write(data)
	return fmt.Sprintf("%X", h.Sum(nil))
}

//Need to decide about what charachteristics of the cartificate
//are going to be saved in the observatory
type SSLCerts struct {
	SHA1               string   `json:"sha1"`
	SubjectKeyId       string   `json:"subKeyID"`
	Version            int      `json:"version"`
	SignatureAlgorithm string   `json:"sigAlg"`
	PublicKeyAlgorithm string   `json:"pubKeyAlg"`
	Subject            string   `json:"subject"`
	DNSNames           []string `json:"domain(s)"`
	NotBefore          string   `json:"notBefore"`
	NotAfter           string   `json:"notAfter"`
	ExpiresIn          string   `json:"Exp"`
	Issuer             string   `json:"issuer"`
	AuthorityKeyId     string   `json:"authKeyID"`
}

func checkHost(domainName string, skipVerify bool) ([]SSLCerts, error) {

	//Connect network
	ipConn, err := net.DialTimeout("tcp", domainName, 10000*time.Millisecond)
	if err != nil {
		return nil, err
	}
	defer ipConn.Close()

	// Configure tls to look at domainName
	config := tls.Config{ServerName: domainName,
		InsecureSkipVerify: skipVerify}

	// Connect to tls
	conn := tls.Client(ipConn, &config)
	defer conn.Close()

	// Handshake with TLS to get certs
	hsErr := conn.Handshake()
	if hsErr != nil {
		return nil, hsErr
	}

	certs := conn.ConnectionState().PeerCertificates

	if certs == nil || len(certs) < 1 {
		return nil, errors.New("Could not get server's certificate from the TLS connection.")
	}

	sslcerts := make([]SSLCerts, len(certs))

	for i, cert := range certs {
		s := SSLCerts{SHA1: SHA1Hash(cert.Raw), SubjectKeyId: fmt.Sprintf("%X", cert.SubjectKeyId),
			Version: cert.Version, SignatureAlgorithm: signatureAlgorithm[cert.SignatureAlgorithm],
			PublicKeyAlgorithm: publicKeyAlgorithm[cert.PublicKeyAlgorithm],
			Subject:            cert.Subject.CommonName,
			DNSNames:           cert.DNSNames,
			//times are calcualated locally for the time being
			//maybe this needs to change and keep the original time
			NotBefore:      cert.NotBefore.Local().String(),
			NotAfter:       cert.NotAfter.Local().String(),
			ExpiresIn:      ExpiresIn(cert.NotAfter.Local()),
			Issuer:         cert.Issuer.CommonName,
			AuthorityKeyId: fmt.Sprintf("%X", cert.AuthorityKeyId),
		}

		sslcerts[i] = s

	}

	return sslcerts, nil
}

func OutputToStd(canonicalName string, certs []SSLCerts) {

	for i, cert := range certs {
		if i == 0 {
			fmt.Printf("Certificate chain for %s\n", canonicalName)
		}
		fmt.Printf("Subject: %s\n", cert.Subject)
		fmt.Printf("\tSHA1: %s\n", cert.SHA1)
		fmt.Printf("\tSubjectKeyId: %s\n", cert.SubjectKeyId)
		fmt.Printf("\tSignatureAlgorithm: %s\n", cert.SignatureAlgorithm)
		fmt.Printf("\tPublicKeyAlgorithm: %s\n", cert.PublicKeyAlgorithm)
		fmt.Printf("\tDNSNames: %v\n", cert.DNSNames)
		fmt.Printf("\tNotBefore: %s\n", cert.NotBefore)
		fmt.Printf("\tNotAfter: %s\n", cert.NotAfter)
		fmt.Printf("\tExpiresIn: %s\n", cert.ExpiresIn)
		fmt.Printf("\tIssuer: %s\n", cert.Issuer)
		fmt.Printf("\tAuthorityKeyId: %s\n", cert.AuthorityKeyId)
	}
}

func Usage() {
	fmt.Printf("Usage: %s -d <domain name> -p <port> -o <outfile>\n", programName)
	flag.PrintDefaults()
}

func main() {
	var domainName, port, outfile, canonicalName string

	flag.StringVar(&domainName, "d", "", "Domain name or IP Address of the host you want to check ssl certificates of.")
	flag.StringVar(&port, "p", "443", "Port Number")
	flag.StringVar(&outfile, "o", "output.json", "Output file")
	var printJson = flag.Bool("j", false, "output certs in JSON format to stdout")
	flag.Parse()

	if len(os.Args) < 3 || (domainName == "") {
		Usage()
		os.Exit(1)
	}

	canonicalName = domainName + ":" + port

	var ce string
	var err error
	var certs []SSLCerts

	// Catch any misconfigurations
	certs, err = checkHost(canonicalName, false)
	if err != nil {
		ce = fmt.Sprintf("%s", err)
	}

	// proceed to gather the certs, ignoring the warnings
	if certs == nil && err != nil {
		certs, err = checkHost(canonicalName, true)
		if err != nil {
			ce = fmt.Sprintf("%s", err)
		}
	}

	if ce != "" {
		fmt.Printf("WARNING ! :%s\n", ce)
	}

	if *printJson {
		jsonCerts, err := json.MarshalIndent(certs, "", "    ")
		if err != nil {
			panic(err)
		}
		fmt.Printf("%s\n", jsonCerts)
	} else {
		OutputToStd(canonicalName, certs)
	}
}
