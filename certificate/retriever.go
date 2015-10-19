//certRetriever tries to connect to a domain received by a queue (rxQueue). If it succeeds it retrieves the certificate
//chain provided by that domain and publishes it to another queue(txQueue).
package certificate

import (
	// stdlib packages
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"time"
)

type NoTLSCertsErr string

func (f NoTLSCertsErr) Error() string {
	return fmt.Sprintf("No TLS Certs Received from %s", string(f))
}

//HandleCert is the main function called to verify certificates.
//It retrieves certificates and feeds them to handleCertChain. It then returns
//its result.
func HandleCert(domain string) (string, []byte, error) {

	certs, ip, err := retrieveCertFromHost(domain, "443", true)

	if err != nil {
		log.Println("Retrieving certs for %s failed with: %s", domain, err.Error())
		return "", nil, err
	}

	if certs == nil {
		e := new(NoTLSCertsErr)
		return "", nil, e
	}

	var chain = Chain{}

	chain.Domain = domain

	chain.IP = ip

	for _, cert := range certs {

		chain.Certs = append(chain.Certs, base64.StdEncoding.EncodeToString(cert.Raw))

	}

	return handleCertChain(&chain)

}

//retrieveCertFromHost checks the host connectivity and returns the certificate chain ( if any ) provided
//by the domain or an error in every other case.
func retrieveCertFromHost(domainName, port string, skipVerify bool) ([]*x509.Certificate, string, error) {

	config := tls.Config{InsecureSkipVerify: skipVerify}

	canonicalName := domainName + ":" + port

	ip := ""

	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", canonicalName, &config)

	if err != nil {
		return nil, ip, err
	}
	defer conn.Close()

	ip = strings.TrimSuffix(conn.RemoteAddr().String(), ":443")

	certs := conn.ConnectionState().PeerCertificates

	if certs == nil {
		return nil, ip, errors.New("Could not get server's certificate from the TLS connection.")
	}

	return certs, ip, nil
}
