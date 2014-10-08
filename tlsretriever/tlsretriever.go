package tlsretriever

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
)

func CheckHost(domainName, port string) ([]*x509.Certificate, error) {

	config := tls.Config{}

	canonicalName := domainName + ":" + port

	conn, err := tls.Dial("tcp", canonicalName, &config)

	if err != nil{
		panic(err)
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates

	if certs == nil {
		return nil, errors.New("Could not get server's certificate from the TLS connection.")
	}

	return certs, nil
}
