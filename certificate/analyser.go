//certAnalyser provides a client that receives certificates from a queue, processes them and
//indexes them in an ElasticSearch database. The Certificate struct is used as the storage document template
package certificate

import (
	// stdlib packages
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/md5"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	//"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"runtime"
	"strconv"
	"time"

	"github.com/mozilla/TLS-Observer/config"
)

var trustStores []TrustStore

func Setup(c config.ObserverConfig) {

	ts := c.TrustStores
	// Load truststores from configuration. We expect that the truststore names and path
	// are ordered correctly in the configuration, thus if truststore "mozilla" is at
	// position 0 in conf.TrustStores.Name, its path will be found at conf.TrustStores.Path[0]
	for i, name := range ts.Name {
		// load the entire trustore into pooldata, then iterate over each PEM block
		// until all of pooldata is read
		poolData, err := ioutil.ReadFile(ts.Path[i])
		if err != nil {
			log.Fatal("Failed to load", name, "truststore:", err)
		}
		certPool := x509.NewCertPool()
		poollen := 0
		for len(poolData) > 0 {
			// read the next PEM block, ignore non CERTIFICATE entires
			var block *pem.Block
			block, poolData = pem.Decode(poolData)
			if block == nil {
				break
			}
			if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
				continue
			}
			// parse the current PEM block into a certificate, ignore failures
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				log.Println("Warning: could not parse PEM block from", name, "truststore:", err)
				continue
			}
			// if the cert version is 1 or 2, the cert will not contain a CA: True extension
			// so we set it manually instead. This assumes that all certs found in truststores
			// should be considered valid certificate authorities
			if cert.Version < 3 {
				cert.IsCA = true
			}
			certPool.AddCert(cert)

			//Push current certificate to DB as trusted
			v := &ValidationInfo{}
			v.IsValid = true

			parentSignature := ""
			if cert.Subject.CommonName == cert.Issuer.CommonName {
				parentSignature = SHA256Hash(cert.Raw)
			}
			updateCert(cert, parentSignature, "", "", name, v, nil)

			poollen++
		}
		trustStores = append(trustStores, TrustStore{name, certPool})
		log.Println("successfully loaded", poollen, "CA certs from", name, "truststore")
	}

	if len(trustStores) == 0 {
		log.Println("Warning: no loadable trustore found in configuration, using system default")
		defaultName := "default-" + runtime.GOOS
		// nil Root certPool will result in the system defaults being loaded
		trustStores = append(trustStores, TrustStore{defaultName, nil})
	}
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

func panicIf(err error) bool {
	if err != nil {
		log.Println(fmt.Sprintf("%s", err))
		return true
	}

	return false
}

//handleCertChain takes the chain retrieved from the queue and tries to validate it
//against each of the truststores provided.
func handleCertChain(chain *Chain) (string, []byte, error) {

	var intermediates []*x509.Certificate
	var leafCert *x509.Certificate
	leafCert = nil

	for _, data := range chain.Certs { //create certificate chain from chain struct

		certRaw, err := base64.StdEncoding.DecodeString(data)
		panicIf(err)

		var cert *x509.Certificate
		cert, err = x509.ParseCertificate(certRaw)
		panicIf(err)

		if !cert.IsCA {
			leafCert = cert
		} else {
			intermediates = append(intermediates, cert)
		}
	}

	if leafCert == nil {
		log.Println("No Server certificate found in chain received by:" + chain.Domain)
	}

	var certmap = make(map[string]Stored)

	//validate against each truststore
	for _, curTS := range trustStores {

		if leafCert != nil {

			if isChainValid(leafCert, intermediates, &curTS, chain.Domain, chain.IP, certmap) {
				continue
			}
		}

		// to end up here either there was no leaf certificate retrieved
		// or it was retrieved but it was not valid so we must check the remainder of the chain
		for i, cert := range intermediates {

			inter := append(intermediates[:i], intermediates[i+1:]...)

			isChainValid(cert, inter, &curTS, chain.Domain, chain.IP, certmap)
			//should we break if/when this validates?
		}

	}

	//	for id, certS := range certmap {

	//		pushCertificate(id, certS.Certificate, certS.Raw)

	//	}

	return "", nil, nil
}

//isChainValid creates the valid certificate chains by combining the chain retrieved with the provided truststore.
//It return true if it finds at least on validation chain or false if no valid chain of trust can be created.
//It also updates the certificate map which gets pushed at the end of each iteration.
func isChainValid(serverCert *x509.Certificate, intermediates []*x509.Certificate, curTS *TrustStore, domain, IP string, certmap map[string]Stored) bool {

	valInfo := &ValidationInfo{}

	valInfo.IsValid = true

	inter := x509.NewCertPool()
	for _, in := range intermediates {
		inter.AddCert(in)
	}

	dnsName := domain

	if serverCert.IsCA {
		dnsName = serverCert.Subject.CommonName
	}

	opts := x509.VerifyOptions{
		DNSName:       dnsName,
		Intermediates: inter,
		Roots:         curTS.Certs,
	}

	chains, err := serverCert.Verify(opts)

	if err == nil {

		for i, ch := range chains {
			log.Println("Trust chain no:", strconv.Itoa(i), "length: ", len(ch))
			for _, cert := range ch {

				parentSignature := ""
				c := getFirstParent(cert, ch)

				if c != nil {
					parentSignature = SHA256Hash(c.Raw)
				} else {
					log.Println("could not retrieve parent for " + dnsName)
				}

				updateCert(cert, parentSignature, domain, IP, curTS.Name, valInfo, certmap)
			}
		}
		return true
	} else {
		if len(chains) > 0 {
			log.Println("validation error but validation chain populated for: " + dnsName)
		}

		valInfo.ValidationError = err.Error()
		valInfo.IsValid = false

		parentSignature := ""
		c := getFirstParent(serverCert, intermediates)

		if c != nil {
			parentSignature = SHA256Hash(c.Raw)
		} else {
			log.Println("could not retrieve parent for " + dnsName)
		}

		updateCert(serverCert, parentSignature, domain, IP, curTS.Name, valInfo, certmap)

		return false
	}

}

//getFirstParent returns the first parent found for a certificate in a given certificate list ( does not verify signature)
func getFirstParent(cert *x509.Certificate, certs []*x509.Certificate) *x509.Certificate {
	for _, c := range certs {
		if cert.Issuer.CommonName == c.Subject.CommonName { //TODO : consider changing this check with validating check
			return c
		}
	}
	//parent not found
	return nil
}

//updateCert takes the input certificate and updates the map holding all the certificates to be pushed.
//If the certificates has already been inserted it updates the existing record else it creates it.
func updateCert(cert *x509.Certificate, parentSignature string, domain, ip, TSName string, valInfo *ValidationInfo, certmap map[string]Stored) {

	id := SHA256Hash(cert.Raw)
	if !cert.IsCA {
		id = id + "--" + domain
	}

	if storedStruct, ok := certmap[id]; !ok {

		certmap[id] = Stored{Certificate: certtoStored(cert, parentSignature, domain, ip, TSName, valInfo), Raw: cert.Raw}

	} else {

		storedCert := storedStruct.Certificate

		parentFound := false

		for _, p := range storedCert.ParentSignature {

			if parentSignature == p {
				parentFound = true
				break
			}
		}

		if !parentFound {
			storedCert.ParentSignature = append(storedCert.ParentSignature, parentSignature)
		}

		if !storedCert.CA {

			if storedCert.ScanTarget != domain {
				log.Println("Stored Cert - ", id, " - Domain found:", domain, "Domain Stored: ", storedCert.ScanTarget)
			}

			//add IP ( single domain may be served by multiple IPs )
			ipFound := false

			for _, i := range storedCert.IPs {
				if ip == i {
					ipFound = true
					break
				}
			}

			if !ipFound {
				storedCert.IPs = append(storedCert.IPs, ip)
			}
		}

		storedCert.ValidationInfo[TSName] = *valInfo

		certmap[id] = Stored{Certificate: storedCert, Raw: cert.Raw}
	}

}

//getCert tries to retrieve a stored certificate from the database.
//If the document is not found it returns an error.
func getCert(sha1 string) (Certificate, error) {

	stored := Certificate{}

	//get a cert from the db
	log.Println(sha1)

	var err error

	return stored, err
}

func getExtKeyUsageAsStringArray(cert *x509.Certificate) []string {

	usage := make([]string, len(cert.ExtKeyUsage))

	for i, eku := range cert.ExtKeyUsage {

		usage[i] = ExtKeyUsage[eku]
	}

	return usage
}

func getKeyUsageAsStringArray(cert *x509.Certificate) []string {

	var usage []string
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

	extensions := Extensions{}

	extensions.AuthorityKeyId = []byte(base64.StdEncoding.EncodeToString(cert.AuthorityKeyId))
	extensions.SubjectKeyId = []byte(base64.StdEncoding.EncodeToString(cert.SubjectKeyId))

	extensions.KeyUsage = getKeyUsageAsStringArray(cert)

	extensions.ExtendedKeyUsage = getExtKeyUsageAsStringArray(cert)

	extensions.SubjectAlternativeName = cert.DNSNames

	extensions.CRLDistributionPoints = cert.CRLDistributionPoints

	return extensions

}

func getPublicKeyInfo(cert *x509.Certificate) SubjectPublicKeyInfo {

	var pubInfo = SubjectPublicKeyInfo{}

	pubInfo.PublicKeyAlgorithm = PublicKeyAlgorithm[cert.PublicKeyAlgorithm]

	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		pubInfo.RSAModulusSize = float64(pub.N.BitLen())
		pubInfo.RSAExponent = float64(pub.E)

	case *dsa.PublicKey:
		textInt, err := pub.G.MarshalText()

		if err == nil {
			pubInfo.DSA_G = string(textInt)
		} else {
			panicIf(err)
		}

		textInt, err = pub.P.MarshalText()

		if err == nil {
			pubInfo.DSA_P = string(textInt)
		} else {
			panicIf(err)
		}

		textInt, err = pub.Q.MarshalText()

		if err == nil {
			pubInfo.DSA_Q = string(textInt)
		} else {
			panicIf(err)
		}

		textInt, err = pub.Y.MarshalText()

		if err == nil {
			pubInfo.DSA_Y = string(textInt)
		} else {
			panicIf(err)
		}

	case *ecdsa.PublicKey:

		pubInfo.ECDSACurveType = strconv.Itoa(pub.Curve.Params().BitSize)
		pubInfo.ECDSA_Y = float64(pub.Y.BitLen())
		pubInfo.ECDSA_X = float64(pub.X.BitLen())
	}

	return pubInfo

}

//certtoStored returns a Certificate struct created from a X509.Certificate
func certtoStored(cert *x509.Certificate, parentSignature, domain, ip string, TSName string, valInfo *ValidationInfo) Certificate {

	var stored = Certificate{}

	stored.Version = float64(cert.Version)

	stored.SignatureAlgorithm = SignatureAlgorithm[cert.SignatureAlgorithm]

	stored.SubjectPublicKeyInfo = getPublicKeyInfo(cert)

	stored.Issuer.Country = cert.Issuer.Country
	stored.Issuer.Organisation = cert.Issuer.Organization
	stored.Issuer.OrgUnit = cert.Issuer.OrganizationalUnit
	stored.Issuer.CommonName = cert.Issuer.CommonName

	stored.Subject.Country = cert.Subject.Country
	stored.Subject.Organisation = cert.Subject.Organization
	stored.Subject.OrgUnit = cert.Subject.OrganizationalUnit
	stored.Subject.CommonName = cert.Subject.CommonName

	nbtime := cert.NotBefore.UTC()
	natime := cert.NotAfter.UTC()
	stored.Validity.NotBefore = fmt.Sprintf("%d-%02d-%02dT%02d:%02d:%02d", nbtime.Year(), nbtime.Month(), nbtime.Day(), nbtime.Hour(), nbtime.Minute(), nbtime.Second())
	stored.Validity.NotAfter = fmt.Sprintf("%d-%02d-%02dT%02d:%02d:%02d", natime.Year(), natime.Month(), natime.Day(), natime.Hour(), natime.Minute(), natime.Second())

	stored.X509v3Extensions = getCertExtensions(cert)

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

	stored.FirstSeenTimestamp = fmt.Sprintf("%d-%02d-%02dT%02d:%02d:%02d", t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second())
	stored.LastSeenTimestamp = fmt.Sprintf("%d-%02d-%02dT%02d:%02d:%02d", t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second())

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

	return stored

}

//printRawCertExtensions Print raw extension info
//for debugging purposes
func printRawCertExtensions(cert *x509.Certificate) {

	for i, extension := range cert.Extensions {

		var numbers string
		for num, num2 := range extension.Id {

			numbers = numbers + " " + "[" + strconv.Itoa(num) + " " + strconv.Itoa(num2) + "]"

		}
		log.Println("//", strconv.Itoa(i), ": {", numbers, "}", string(extension.Value))
	}

}
