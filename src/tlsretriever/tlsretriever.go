package tlsretriever

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"strings"
)

func CheckHost(domainName, port string, skipVerify bool) ([]*x509.Certificate, string, error) {

	config := tls.Config{InsecureSkipVerify: skipVerify}

	canonicalName := domainName + ":" + port

	ip := ""

	conn, err := tls.Dial("tcp", canonicalName, &config)

	if err != nil {
		return nil, ip, err
	}
	defer conn.Close()

	ip = strings.TrimRight(conn.RemoteAddr().String(), ":443")

	certs := conn.ConnectionState().PeerCertificates

	if certs == nil {
		return nil, ip, errors.New("Could not get server's certificate from the TLS connection.")
	}

	return certs, ip, nil
}
