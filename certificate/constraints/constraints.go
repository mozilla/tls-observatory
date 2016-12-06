package certconstraints

import (
	constraintsx509 "constraintcrypto/x509"
	"crypto/x509"
	"fmt"
	"net"
	"time"
)

type Constraints struct {
	PermittedDNSDomains  []string
	ExcludedDNSDomains   []string
	PermittedIPAddresses []net.IPNet
	ExcludedIPAddresses  []net.IPNet
}


// Get returns the Constraints for a given x509 certificate
func Get(cert *x509.Certificate) (*Constraints, error) {
	certs, err := constraintsx509.ParseCertificates(cert.Raw)
	if err != nil {
		return nil, err
	}
	if len(certs) != 1 {
		return nil, fmt.Errorf("cert.Raw must contain exactly one certificate")
	}
	constraintCert := certs[0]

	return &Constraints{
		PermittedDNSDomains: constraintCert.PermittedDNSDomains,
		ExcludedDNSDomains: constraintCert.ExcludedDNSDomains,
		PermittedIPAddresses: constraintCert.PermittedIPAddresses,
		ExcludedIPAddresses: constraintCert.ExcludedIPAddresses,
	}, nil
}

func isAllZeros(buf []byte, length int) bool {
	if length > len(buf) {
		return false
	}
	for i:=0; i<length; i++ {
		if buf[i] != 0 {
			return false
		}
	}
	return true
}

// IsTechnicallyConstrained determines if a given certificate is technically constrained.
// Slightly modified from https://github.com/jcjones/gx509/blob/master/gx509/technicalconstraints.go
func IsTechnicallyConstrained(cert *x509.Certificate) bool {
	// There must be Extended Key Usage flags
	if len(cert.ExtKeyUsage) == 0 {
		return false
	}

	// For certificates with a notBefore before 23 August 2016, the
	// id-Netscape-stepUp OID (aka Netscape Server Gated Crypto ("nsSGC")) is
	// treated as equivalent to id-kp-serverAuth.
	nsSGCCutoff := time.Date(2016, time.August, 23, 0, 0, 0, 0, time.UTC)

	stepUpEquivalentToServerAuth := cert.NotBefore.Before(nsSGCCutoff)
	var hasServerAuth bool
	var hasStepUp bool

	for _, usage := range cert.ExtKeyUsage {
		switch usage {
		case x509.ExtKeyUsageAny:
			// Do not permit ExtKeyUsageAny
			return false
		case x509.ExtKeyUsageServerAuth:
			hasServerAuth = true
		case x509.ExtKeyUsageNetscapeServerGatedCrypto:
			hasStepUp = true
		}
	}

	// Must be marked for Server Auth, or have StepUp and be from before the cutoff
	if !(hasServerAuth || (stepUpEquivalentToServerAuth && hasStepUp)) {
		return true
	}

	// For iPAddresses in excludedSubtrees, both IPv4 and IPv6 must be present
	// and the constraints must cover the entire range (0.0.0.0/0 for IPv4 and
	// ::0/0 for IPv6).
	var excludesIPv4 bool
	var excludesIPv6 bool
	constraints, _ := Get(cert)
	for _, cidr := range constraints.ExcludedIPAddresses {
		if cidr.IP.Equal(net.IPv4zero) && isAllZeros(cidr.Mask, net.IPv4len) {
			excludesIPv4 = true
		}
		if cidr.IP.Equal(net.IPv6zero) && isAllZeros(cidr.Mask, net.IPv6len) {
			excludesIPv6 = true
		}
	}

	hasIPAddressInPermittedSubtrees := len(constraints.PermittedIPAddresses) > 0
	hasIPAddressesInExcludedSubtrees := excludesIPv4 && excludesIPv6

	// There must be at least one DNSname constraint
	hasDNSName := len(cert.PermittedDNSDomains) > 0 ||
		len(constraints.ExcludedDNSDomains) > 0

	if hasDNSName && (hasIPAddressInPermittedSubtrees ||
		hasIPAddressesInExcludedSubtrees) {
		return true
	}
	return false
}
