package certconstraints

import (
	// constraintsx509 "constraintcrypto/x509"
	"crypto/x509"
	"fmt"
	"net"
	"time"
)

type Constraints struct {
	PermittedDNSDomains []string
	ExcludedDNSDomains  []string
	PermittedIPRanges   []*net.IPNet
	ExcludedIPRanges    []*net.IPNet
}

// Get returns the Constraints for a given x509 certificate
func Get(cert *x509.Certificate) (*Constraints, error) {
	certs, err := x509.ParseCertificates(cert.Raw)
	if err != nil {
		return nil, err
	}
	if len(certs) != 1 {
		return nil, fmt.Errorf("cert.Raw must contain exactly one certificate")
	}
	constraintCert := certs[0]

	return &Constraints{
		PermittedDNSDomains: constraintCert.PermittedDNSDomains,
		ExcludedDNSDomains:  constraintCert.ExcludedDNSDomains,
		PermittedIPRanges:   constraintCert.PermittedIPRanges,
		ExcludedIPRanges:    constraintCert.ExcludedIPRanges,
	}, nil
}

func isAllZeros(buf []byte, length int) bool {
	if length > len(buf) {
		return false
	}
	for i := 0; i < length; i++ {
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
	for _, cidr := range constraints.ExcludedIPRanges {
		if cidr.IP.Equal(net.IPv4zero) && isAllZeros(cidr.Mask, net.IPv4len) {
			excludesIPv4 = true
		}
		if cidr.IP.Equal(net.IPv6zero) && isAllZeros(cidr.Mask, net.IPv6len) {
			excludesIPv6 = true
		}
	}

	hasIPAddressInPermittedSubtrees := len(constraints.PermittedIPRanges) > 0
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

// IsTechnicallyConstrainedMozPolicyV2_5 determines if a given certificate is technically constrained
// according to the Mozilla Root Store Policy V2.5.
// https://www.mozilla.org/en-US/about/governance/policies/security-group/certs/policy/
func IsTechnicallyConstrainedMozPolicyV2_5(cert *x509.Certificate) bool {
	// The logic from IsTechnicallyConstrained is extended here due to paragraph
	// three of section 5.3.1:
	//
	// If the certificate includes the id-kp-emailProtection extended key usage,
	// it MUST include the Name Constraints X.509v3 extension with constraints on
	// rfc822Name, with at least one name in permittedSubtrees, each such name having
	// its ownership validated according to section 3.2.2.4 of the Baseline Requirements.
	for _, extKeyUsage := range cert.ExtKeyUsage {
		if extKeyUsage == x509.ExtKeyUsageEmailProtection {
			if len(cert.PermittedEmailAddresses) == 0 {
				return false
			}
			break
		}
	}
	return IsTechnicallyConstrained(cert)
}
