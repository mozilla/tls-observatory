package certificate

import (
	"crypto/x509"
)

type Certificate struct {
	ScanTarget             string                    `json:"scanTarget,omitempty"`
	IPs                    []string                  `json:"ips,omitempty"`
	Version                float64                   `json:"version"`
	SignatureAlgorithm     string                    `json:"signatureAlgorithm"`
	Issuer                 Issuer                    `json:"issuer"`
	Validity               Validity                  `json:"validity"`
	Subject                Subject                   `json:"subject"`
	SubjectPublicKeyInfo   SubjectPublicKeyInfo      `json:"subjectPublicKeyInfo"`
	X509v3Extensions       Extensions                `json:"x509v3Extensions"`
	X509v3BasicConstraints string                    `json:"x509v3BasicConstraints"`
	CA                     bool                      `json:"ca"`
	Analysis               interface{}               `json:"analysis"` //for future use...
	ParentSignature        []string                  `json:"parentSignature"`
	ValidationInfo         map[string]ValidationInfo `json:"validationInfo"`
	FirstSeenTimestamp     string                    `json:"firstSeenTimestamp"`
	LastSeenTimestamp      string                    `json:"lastSeenTimestamp"`
	Hashes                 Hashes                    `json:"hashes"`
	Anomalies              string                    `json:"anomalies,omitempty"`
}

type Issuer struct {
	Country      []string `json:"c"`
	Organisation []string `json:"o"`
	OrgUnit      []string `json:"ou"`
	CommonName   string   `json:"cn"`
}

type Hashes struct {
	MD5    string `json:"md5"`
	SHA1   string `json:"sha1"`
	SHA256 string `json:"sha256"`
}

type Validity struct {
	NotBefore string `json:"notBefore"`
	NotAfter  string `json:"notAfter"`
}

type Subject struct {
	Country      []string `json:"c"`
	Organisation []string `json:"o"`
	OrgUnit      []string `json:"ou"`
	CommonName   string   `json:"cn"`
}

type SubjectPublicKeyInfo struct {
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
type Extensions struct {
	AuthorityKeyId         []byte   `json:"authorityKeyId"`
	SubjectKeyId           []byte   `json:"subjectKeyId"`
	KeyUsage               []string `json:"keyUsage"`
	ExtendedKeyUsage       []string `json:"extendedKeyUsage"`
	SubjectAlternativeName []string `json:"subjectAlternativeName"`
	CRLDistributionPoints  []string `json:"crlDistributionPoints"`
}

type X509v3BasicConstraints struct {
	CA       bool        `json:"ca"`
	Analysis interface{} `json:"analysis"`
}

type Chain struct {
	Domain string   `json:"domain"`
	IP     string   `json:"ip"`
	Certs  []string `json:"certs"`
}

type IDs struct {
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

type ValidationInfo struct {
	IsValid         bool   `json:"isValid"`
	ValidationError string `json:"validationError"`
}

type Stored struct {
	Certificate Certificate
	Raw         []byte
}

var SignatureAlgorithm = [...]string{
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

var ExtKeyUsage = [...]string{
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

var PublicKeyAlgorithm = [...]string{
	"UnknownPublicKeyAlgorithm",
	"RSA",
	"DSA",
	"ECDSA",
}
