package certificate

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/md5"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	certconstraints "github.com/mozilla/tls-observatory/certificate/constraints"
)

const (
	Ubuntu_TS_name    = "Ubuntu"
	Mozilla_TS_name   = "Mozilla"
	Microsoft_TS_name = "Microsoft"
	Apple_TS_name     = "Apple"
	Android_TS_name   = "Android"

	Default_Cisco_Umbrella_Rank = 2147483647 // max positive value of postgres integer
)

type Certificate struct {
	ID                     int64                     `json:"id"`
	Serial                 string                    `json:"serialNumber"`
	ScanTarget             string                    `json:"scanTarget,omitempty"`
	IPs                    []string                  `json:"ips,omitempty"`
	Version                int                       `json:"version"`
	SignatureAlgorithm     string                    `json:"signatureAlgorithm"`
	Issuer                 Subject                   `json:"issuer"`
	Validity               Validity                  `json:"validity"`
	Subject                Subject                   `json:"subject"`
	Key                    SubjectPublicKeyInfo      `json:"key"`
	X509v3Extensions       Extensions                `json:"x509v3Extensions"`
	X509v3BasicConstraints string                    `json:"x509v3BasicConstraints"`
	CA                     bool                      `json:"ca"`
	Analysis               interface{}               `json:"analysis,omitempty"` //for future use...
	ParentSignature        []string                  `json:"parentSignature,omitempty"`
	ValidationInfo         map[string]ValidationInfo `json:"validationInfo"`
	FirstSeenTimestamp     time.Time                 `json:"firstSeenTimestamp"`
	LastSeenTimestamp      time.Time                 `json:"lastSeenTimestamp"`
	Hashes                 Hashes                    `json:"hashes"`
	Raw                    string                    `json:"Raw"`
	CiscoUmbrellaRank      int64                     `json:"ciscoUmbrellaRank"`
	Anomalies              string                    `json:"anomalies,omitempty"`
	MozillaPolicyV2_5      MozillaPolicy             `json:"mozillaPolicyV2_5"`
}

type MozillaPolicy struct {
	IsTechnicallyConstrained bool
}

type Hashes struct {
	MD5               string `json:"md5,omitempty"`
	SHA1              string `json:"sha1,omitempty"`
	SHA256            string `json:"sha256,omitempty"`
	SPKISHA256        string `json:"spki-sha256,omitempty"`
	SubjectSPKISHA256 string `json:"subject-spki-sha256,omitempty"`
	PKPSHA256         string `json:"pin-sha256,omitempty"`
}

type Validity struct {
	NotBefore time.Time `json:"notBefore"`
	NotAfter  time.Time `json:"notAfter"`
}

type Subject struct {
	ID           int64    `json:"id,omitempty"`
	Country      []string `json:"c,omitempty"`
	Organisation []string `json:"o,omitempty"`
	OrgUnit      []string `json:"ou,omitempty"`
	CommonName   string   `json:"cn,omitempty"`
}

type SubjectPublicKeyInfo struct {
	Alg      string  `json:"alg,omitempty"`
	Size     float64 `json:"size,omitempty"`
	Exponent float64 `json:"exponent,omitempty"`
	X        string  `json:"x,omitempty"`
	Y        string  `json:"y,omitempty"`
	P        string  `json:"p,omitempty"`
	Q        string  `json:"q,omitempty"`
	G        string  `json:"g,omitempty"`
	Curve    string  `json:"curve,omitempty"`
}

//Currently exporting extensions that are already decoded into the x509 Certificate structure
type Extensions struct {
	AuthorityKeyId           string   `json:"authorityKeyId"`
	SubjectKeyId             string   `json:"subjectKeyId"`
	KeyUsage                 []string `json:"keyUsage"`
	ExtendedKeyUsage         []string `json:"extendedKeyUsage"`
	ExtendedKeyUsageOID      []string `json:"extendedKeyUsageOID"`
	SubjectAlternativeName   []string `json:"subjectAlternativeName"`
	CRLDistributionPoints    []string `json:"crlDistributionPoint"`
	PolicyIdentifiers        []string `json:"policyIdentifiers,omitempty"`
	PermittedDNSDomains      []string `json:"permittedDNSNames,omitempty"`
	PermittedIPAddresses     []string `json:"permittedIPAddresses,omitempty"`
	ExcludedDNSDomains       []string `json:"excludedDNSNames,omitempty"`
	ExcludedIPAddresses      []string `json:"excludedIPAddresses,omitempty"`
	IsTechnicallyConstrained bool     `json:"isTechnicallyConstrained"`
}

type X509v3BasicConstraints struct {
	CA       bool        `json:"ca"`
	Analysis interface{} `json:"analysis,omitempty"`
}

type Chain struct {
	Domain string `json:"domain"`
	IP     string `json:"ip"`
	// base64 DER encoded certificates
	Certs []string `json:"certs"`
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
	IsValid         bool   `json:"isValid,omitempty"`
	ValidationError string `json:"validationError,omitempty"`
}

type Trust struct {
	ID               int64
	CertID           int64
	IssuerID         int64
	Timestamp        time.Time
	TrustUbuntu      bool
	TrustMozilla     bool
	TrustedMicrosoft bool
	TrustedApple     bool
	TrustedAndroid   bool
	Current          bool
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
	"ExtKeyUsageMicrosoftCommercialCodeSigning",
	"ExtKeyUsageMicrosoftKernelCodeSigning",
}

var ExtKeyUsageOID = [...]string{
	asn1.ObjectIdentifier{2, 5, 29, 37, 0}.String(),                 // ExtKeyUsageAny
	asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}.String(),       // ExtKeyUsageServerAuth
	asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}.String(),       // ExtKeyUsageClientAuth
	asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 3}.String(),       // ExtKeyUsageCodeSigning
	asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 4}.String(),       // ExtKeyUsageEmailProtection
	asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 5}.String(),       // ExtKeyUsageIPSECEndSystem
	asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 6}.String(),       // ExtKeyUsageIPSECTunnel
	asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 7}.String(),       // ExtKeyUsageIPSECUser
	asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}.String(),       // ExtKeyUsageTimeStamping
	asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 9}.String(),       // ExtKeyUsageOCSPSigning
	asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 3}.String(), // ExtKeyUsageMicrosoftServerGatedCrypto
	asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 4, 1}.String(),     // ExtKeyUsageNetscapeServerGatedCrypto
	asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 22}.String(), // ExtKeyUsageMicrosoftCommercialCodeSigning
	asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 61, 1, 1}.String(), // ExtKeyUsageMicrosoftKernelCodeSigning
}

var PublicKeyAlgorithm = [...]string{
	"UnknownPublicKeyAlgorithm",
	"RSA",
	"DSA",
	"ECDSA",
}

func SubjectSPKISHA256(cert *x509.Certificate) string {
	h := sha256.New()
	h.Write(cert.RawSubject)
	h.Write(cert.RawSubjectPublicKeyInfo)
	return fmt.Sprintf("%X", h.Sum(nil))
}

func SPKISHA256(cert *x509.Certificate) string {
	h := sha256.New()
	h.Write(cert.RawSubjectPublicKeyInfo)
	return fmt.Sprintf("%X", h.Sum(nil))
}

func PKPSHA256Hash(cert *x509.Certificate) string {
	h := sha256.New()
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey, *dsa.PublicKey, *ecdsa.PublicKey:
		der, _ := x509.MarshalPKIXPublicKey(pub)
		h.Write(der)
	default:
		return ""
	}
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func SHA256Hash(data []byte) string {
	h := sha256.Sum256(data)
	return fmt.Sprintf("%X", h[:])
}

func MD5Hash(data []byte) string {
	h := md5.Sum(data)
	return fmt.Sprintf("%X", h[:])
}

func SHA1Hash(data []byte) string {
	h := sha1.Sum(data)
	return fmt.Sprintf("%X", h[:])
}

//GetBooleanValidity converts the validation info map to DB booleans
func (c Certificate) GetBooleanValidity() (trusted_ubuntu, trusted_mozilla, trusted_microsoft, trusted_apple, trusted_android bool) {

	//check Ubuntu validation info
	valInfo, ok := c.ValidationInfo[Ubuntu_TS_name]

	if !ok {
		trusted_ubuntu = false
	} else {
		trusted_ubuntu = valInfo.IsValid
	}

	//check Mozilla validation info
	valInfo, ok = c.ValidationInfo[Mozilla_TS_name]

	if !ok {
		trusted_mozilla = false
	} else {
		trusted_mozilla = valInfo.IsValid
	}

	//check Microsoft validation info
	valInfo, ok = c.ValidationInfo[Microsoft_TS_name]

	if !ok {
		trusted_microsoft = false
	} else {
		trusted_microsoft = valInfo.IsValid
	}

	//check Apple validation info
	valInfo, ok = c.ValidationInfo[Apple_TS_name]

	if !ok {
		trusted_apple = false
	} else {
		trusted_apple = valInfo.IsValid
	}

	//check Android validation info
	valInfo, ok = c.ValidationInfo[Android_TS_name]

	if !ok {
		trusted_android = false
	} else {
		trusted_android = valInfo.IsValid
	}
	return
}

// GetValidityMap converts boolean validity variables to a validity map.
func GetValidityMap(trusted_ubuntu, trusted_mozilla, trusted_microsoft, trusted_apple, trusted_android bool) map[string]ValidationInfo {

	vUbuntu := ValidationInfo{IsValid: trusted_ubuntu}
	vMozilla := ValidationInfo{IsValid: trusted_mozilla}
	vMicrosoft := ValidationInfo{IsValid: trusted_microsoft}
	vApple := ValidationInfo{IsValid: trusted_apple}
	vAndroid := ValidationInfo{IsValid: trusted_android}

	m := make(map[string]ValidationInfo)

	m[Ubuntu_TS_name] = vUbuntu
	m[Mozilla_TS_name] = vMozilla
	m[Microsoft_TS_name] = vMicrosoft
	m[Apple_TS_name] = vApple
	m[Android_TS_name] = vAndroid

	return m

}

func getExtKeyUsages(cert *x509.Certificate) (usage []string) {
	for _, eku := range cert.ExtKeyUsage {
		usage = append(usage, ExtKeyUsage[eku])
	}
	for _, unknownEku := range cert.UnknownExtKeyUsage {
		usage = append(usage, unknownEku.String())
	}
	return usage
}

func getExtKeyUsageOIDs(cert *x509.Certificate) (usage []string) {
	for _, eku := range cert.ExtKeyUsage {
		usage = append(usage, ExtKeyUsageOID[eku])
	}
	for _, unknownEku := range cert.UnknownExtKeyUsage {
		usage = append(usage, unknownEku.String())
	}
	return usage
}

func getPolicyIdentifiers(cert *x509.Certificate) []string {
	identifiers := make([]string, 0)
	for _, pi := range cert.PolicyIdentifiers {
		identifiers = append(identifiers, pi.String())
	}
	return identifiers
}

func getKeyUsages(cert *x509.Certificate) []string {
	usage := make([]string, 0)
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

//getCertExtensions currently stores only the extensions that are already exported by GoLang
//(in the x509 Certificate Struct)
func getCertExtensions(cert *x509.Certificate) Extensions {
	// initialize []string to store them as `[]` instead of null
	san := make([]string, 0)
	san = append(san, cert.DNSNames...)
	crld := make([]string, 0)
	crld = append(crld, cert.CRLDistributionPoints...)
	constraints, _ := certconstraints.Get(cert)
	ipNetSliceToStringSlice := func(in []*net.IPNet) []string {
		out := make([]string, 0)
		for _, ipnet := range in {
			out = append(out, ipnet.String())
		}
		return out
	}
	permittedIPAddresses := ipNetSliceToStringSlice(constraints.PermittedIPRanges)
	excludedIPAddresses := ipNetSliceToStringSlice(constraints.ExcludedIPRanges)
	ext := Extensions{
		AuthorityKeyId:           base64.StdEncoding.EncodeToString(cert.AuthorityKeyId),
		SubjectKeyId:             base64.StdEncoding.EncodeToString(cert.SubjectKeyId),
		KeyUsage:                 getKeyUsages(cert),
		ExtendedKeyUsage:         getExtKeyUsages(cert),
		ExtendedKeyUsageOID:      getExtKeyUsageOIDs(cert),
		PolicyIdentifiers:        getPolicyIdentifiers(cert),
		SubjectAlternativeName:   san,
		CRLDistributionPoints:    crld,
		PermittedDNSDomains:      constraints.PermittedDNSDomains,
		ExcludedDNSDomains:       constraints.ExcludedDNSDomains,
		PermittedIPAddresses:     permittedIPAddresses,
		ExcludedIPAddresses:      excludedIPAddresses,
		IsTechnicallyConstrained: certconstraints.IsTechnicallyConstrained(cert),
	}
	return ext
}

func getMozillaPolicyV2_5(cert *x509.Certificate) MozillaPolicy {
	return MozillaPolicy{IsTechnicallyConstrained: certconstraints.IsTechnicallyConstrainedMozPolicyV2_5(cert)}
}

func getPublicKeyInfo(cert *x509.Certificate) (SubjectPublicKeyInfo, error) {
	pubInfo := SubjectPublicKeyInfo{
		Alg: PublicKeyAlgorithm[cert.PublicKeyAlgorithm],
	}

	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		pubInfo.Size = float64(pub.N.BitLen())
		pubInfo.Exponent = float64(pub.E)

	case *dsa.PublicKey:
		pubInfo.Size = float64(pub.Y.BitLen())
		textInt, err := pub.G.MarshalText()

		if err == nil {
			pubInfo.G = string(textInt)
		} else {
			return pubInfo, err
		}

		textInt, err = pub.P.MarshalText()

		if err == nil {
			pubInfo.P = string(textInt)
		} else {
			return pubInfo, err
		}

		textInt, err = pub.Q.MarshalText()

		if err == nil {
			pubInfo.Q = string(textInt)
		} else {
			return pubInfo, err
		}

		textInt, err = pub.Y.MarshalText()

		if err == nil {
			pubInfo.Y = string(textInt)
		} else {
			return pubInfo, err
		}

	case *ecdsa.PublicKey:
		pubInfo.Size = float64(pub.Curve.Params().BitSize)
		pubInfo.Curve = pub.Curve.Params().Name
		pubInfo.Y = pub.Y.String()
		pubInfo.X = pub.X.String()
	}

	return pubInfo, nil

}

func GetHexASN1Serial(cert *x509.Certificate) (serial string, err error) {
	m, err := asn1.Marshal(cert.SerialNumber)
	if err != nil {
		return
	}
	var rawValue asn1.RawValue
	_, err = asn1.Unmarshal(m, &rawValue)
	if err != nil {
		return
	}
	serial = fmt.Sprintf("%X", rawValue.Bytes)
	return
}

//certtoStored returns a Certificate struct created from a X509.Certificate
func CertToStored(cert *x509.Certificate, parentSignature, domain, ip string, TSName string, valInfo *ValidationInfo) Certificate {
	var (
		err    error
		stored = Certificate{}
	)
	// initialize []string to never store them as null
	stored.ParentSignature = make([]string, 0)
	stored.IPs = make([]string, 0)

	stored.Version = cert.Version

	// If there's an error, we just store the zero value ("")
	serial, _ := GetHexASN1Serial(cert)
	stored.Serial = serial

	stored.SignatureAlgorithm = SignatureAlgorithm[cert.SignatureAlgorithm]

	stored.Key, err = getPublicKeyInfo(cert)
	if err != nil {
		log.Printf("Failed to retrieve public key information: %v. Continuing anyway.", err)
	}

	stored.Issuer.Country = cert.Issuer.Country
	stored.Issuer.Organisation = cert.Issuer.Organization
	stored.Issuer.OrgUnit = cert.Issuer.OrganizationalUnit
	stored.Issuer.CommonName = cert.Issuer.CommonName

	stored.Subject.Country = cert.Subject.Country
	stored.Subject.Organisation = cert.Subject.Organization
	stored.Subject.OrgUnit = cert.Subject.OrganizationalUnit
	stored.Subject.CommonName = cert.Subject.CommonName

	stored.Validity.NotBefore = cert.NotBefore.UTC()
	stored.Validity.NotAfter = cert.NotAfter.UTC()

	stored.X509v3Extensions = getCertExtensions(cert)

	stored.MozillaPolicyV2_5 = getMozillaPolicyV2_5(cert)

	//below check tries to hack around the basic constraints extension
	//not being available in versions < 3.
	//Only the IsCa variable is set, as setting X509v3BasicConstraints
	//messes up the validation procedure.
	if cert.Version < 3 {
		stored.CA = cert.IsCA
	} else {
		if cert.BasicConstraintsValid {
			stored.X509v3BasicConstraints = "Critical"
			stored.CA = cert.IsCA
		} else {
			stored.X509v3BasicConstraints = ""
			stored.CA = false
		}
	}

	t := time.Now().UTC()

	stored.FirstSeenTimestamp = t
	stored.LastSeenTimestamp = t

	stored.ParentSignature = append(stored.ParentSignature, parentSignature)

	if !cert.IsCA {
		stored.ScanTarget = domain
		stored.IPs = append(stored.IPs, ip)
	}

	stored.ValidationInfo = make(map[string]ValidationInfo)
	stored.ValidationInfo[TSName] = *valInfo

	stored.Hashes.MD5 = MD5Hash(cert.Raw)
	stored.Hashes.SHA1 = SHA1Hash(cert.Raw)
	stored.Hashes.SHA256 = SHA256Hash(cert.Raw)
	stored.Hashes.SPKISHA256 = SPKISHA256(cert)
	stored.Hashes.SubjectSPKISHA256 = SubjectSPKISHA256(cert)
	stored.Hashes.PKPSHA256 = PKPSHA256Hash(cert)

	stored.Raw = base64.StdEncoding.EncodeToString(cert.Raw)
	stored.CiscoUmbrellaRank = Default_Cisco_Umbrella_Rank

	return stored
}

// ToX509() returns the crypto/x509 version of a certificate
func (cert Certificate) ToX509() (xcert *x509.Certificate, err error) {
	certRaw, err := base64.StdEncoding.DecodeString(cert.Raw)
	if err != nil {
		return
	}
	return x509.ParseCertificate(certRaw)
}

//printRawCertExtensions Print raw extension info
//for debugging purposes
func printRawCertExtensions(cert *x509.Certificate) {

	for i, extension := range cert.Extensions {

		var numbers string
		for num, num2 := range extension.Id {

			numbers = numbers + " " + "[" + strconv.Itoa(num) + " " + strconv.Itoa(num2) + "]"

		}
		fmt.Println("//", strconv.Itoa(i), ": {", numbers, "}", string(extension.Value))
	}

}

// String() prints the subject as a single string, following OpenSSL's display
// format: Subject: C=US, ST=California, L=Mountain View, O=Google Inc, CN=*.google.com
func (s Subject) String() string {
	var comp []string
	if len(s.Country) > 0 {
		comp = append(comp, "C="+strings.Join(s.Country, ", C="))
	}
	if len(s.Organisation) > 0 {
		comp = append(comp, "O="+strings.Join(s.Organisation, ", O="))
	}
	if len(s.OrgUnit) > 0 {
		comp = append(comp, "OU="+strings.Join(s.OrgUnit, ", OU="))
	}
	if len(s.CommonName) > 0 {
		comp = append(comp, "CN="+s.CommonName)
	}
	return strings.Join(comp, ", ")
}

// IsSelfSigned return true if the subject and issuer fields of a certificate
// are identical
func (c Certificate) IsSelfSigned() bool {
	if c.Subject.CommonName != c.Issuer.CommonName ||
		len(c.Subject.Organisation) != len(c.Issuer.Organisation) ||
		len(c.Subject.OrgUnit) != len(c.Issuer.OrgUnit) ||
		len(c.Subject.Country) != len(c.Issuer.Country) {
		return false
	}
	for i, _ := range c.Subject.Organisation {
		if c.Subject.Organisation[i] != c.Issuer.Organisation[i] {
			return false
		}
	}
	for i, _ := range c.Subject.OrgUnit {
		if c.Subject.OrgUnit[i] != c.Issuer.OrgUnit[i] {
			return false
		}
	}
	for i, _ := range c.Subject.Country {
		if c.Subject.Country[i] != c.Issuer.Country[i] {
			return false
		}
	}
	return true
}
