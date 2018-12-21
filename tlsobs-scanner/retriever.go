package main

import (
	// stdlib packages
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/mozilla/tls-observatory/certificate"
	"github.com/sirupsen/logrus"
)

type NoTLSCertsErr string

func (f NoTLSCertsErr) Error() string {
	return fmt.Sprintf("No TLS Certs Received")
}

//HandleCert is the main function called to verify certificates.
//It retrieves certificates and feeds them to handleCertChain. It then returns
//its result.
func handleCert(domain string) (int64, int64, *certificate.Chain, error) {

	certs, ip, err := retrieveCertFromHost(domain, "443", true)

	if err != nil {
		log.WithFields(logrus.Fields{
			"domain": domain,
			"error":  err.Error(),
		}).Warning("Could not retrieve certs")
		return -1, -1, nil, err
	}

	if certs == nil {
		e := new(NoTLSCertsErr)
		return -1, -1, nil, e
	}

	var chain = certificate.Chain{}

	chain.Domain = domain

	chain.IP = ip

	for _, cert := range certs {

		chain.Certs = append(chain.Certs, base64.StdEncoding.EncodeToString(cert.Raw))

	}

	rootCertId, trustId, err := handleCertChain(&chain)
	if err != nil {
		return -1, -1, nil, err
	}
	return rootCertId, trustId, &chain, nil
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
