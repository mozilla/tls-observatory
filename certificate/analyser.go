//certAnalyser provides a client that receives certificates from a queue, processes them and
//indexes them in an ElasticSearch database. The Certificate struct is used as the storage document template
package certificate

import (
	// stdlib packages
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io/ioutil"

	"github.com/Sirupsen/logrus"

	"github.com/mozilla/tls-observatory/config"
	pg "github.com/mozilla/tls-observatory/database"
	"github.com/mozilla/tls-observatory/logger"
)

var trustStores []TrustStore
var log = logger.GetLogger()

var TS = []string{ubuntu_TS_name, mozilla_TS_name, microsoft_TS_name, apple_TS_name, android_TS_name}

func Setup(c config.Config, DB *pg.DB) {
	ts := c.TrustStores

	db = DB

	for _, name := range TS {

		path := ""

		switch name {
		case ubuntu_TS_name:
			path = ts.UbuntuTS

		case mozilla_TS_name:
			path = ts.MozillaTS

		case microsoft_TS_name:
			path = ts.MicrosoftTS

		case apple_TS_name:
			path = ts.AppleTS

		case android_TS_name:
			path = ts.AndroidTS

		default:

			log.WithFields(logrus.Fields{
				"tsname": name,
			}).Warning("Invalid Truststore name.")
		}

		log.WithFields(logrus.Fields{
			"tsname": name,
			"path":   path,
		}).Debug("Loading Truststore")

		// load the entire trustore into pooldata, then iterate over each PEM block
		// until all of pooldata is read
		poolData, err := ioutil.ReadFile(path)
		if err != nil {
			log.WithFields(logrus.Fields{
				"tsname": name,
				"error":  err.Error(),
			}).Warning("Failed to load truststore")
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
				log.WithFields(logrus.Fields{
					"tsname":  name,
					"cert no": poollen + 1,
					"error":   err.Error(),
				}).Warning("Could not parse PEM block")
				continue
			}
			// if the cert version is 1 or 2, the cert will not contain a CA: True extension
			// so we set it manually instead. This assumes that all certs found in truststoresfile:///media/Projects/GoProjects/src/github.com/mozilla/TLS-Observer/certificate/analyserPool.go

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

			var id int64
			id = -1
			id, err = GetCertIDWithSHA256Fingerprint(SHA256Hash(cert.Raw))

			if err != nil {

				log.WithFields(logrus.Fields{
					"tsname":      name,
					"certificate": SHA256Hash(cert.Raw),
					"error":       err.Error(),
				}).Error("Could not check if certificate is in db")
			}

			if id == -1 {

				vinfo := &ValidationInfo{}
				vinfo.IsValid = true
				vinfo.ValidationError = ""

				st := certtoStored(cert, parentSignature, "", "", name, vinfo)
				id, err = InsertCertificatetoDB(&st)

				if err != nil {
					log.WithFields(logrus.Fields{
						"tsname":      name,
						"certificate": SHA256Hash(cert.Raw),
						"error":       err.Error(),
					}).Error("Could not insert certificate in db")
				}
			} else {
				UpdateCertLastSeenWithID(id)
			}

			poollen++
		}
		trustStores = append(trustStores, TrustStore{name, certPool})
		log.WithFields(logrus.Fields{
			"tsname":              name,
			"certificates loaded": poollen,
		}).Info("Successfully loaded TS ")
	}

	if len(trustStores) == 0 {
		log.Error("No truststores loaded, TLS certificate retrieval & analysis won't be available")
	}
}

//handleCertChain takes the chain retrieved from the queue and tries to validate it
//against each of the truststores provided.
func handleCertChain(chain *Chain) (int64, int64, error) {

	var intermediates []*x509.Certificate
	var leafCert *x509.Certificate
	leafCert = nil

	for chaincertno, data := range chain.Certs { //create certificate chain from chain struct

		certRaw, err := base64.StdEncoding.DecodeString(data)
		if err != nil {

			log.WithFields(logrus.Fields{
				"domain":  chain.Domain,
				"cert no": chaincertno,
				"error":   err.Error(),
			}).Warning("Could not decode raw cert from base64")

		}

		var cert *x509.Certificate
		cert, err = x509.ParseCertificate(certRaw)

		if err != nil {
			log.WithFields(logrus.Fields{
				"domain":  chain.Domain,
				"cert no": chaincertno,
				"error":   err.Error(),
			}).Warning("Could not parse raw cert")
		}

		if !cert.IsCA {
			leafCert = cert
		} else {
			intermediates = append(intermediates, cert)
		}
	}

	if leafCert == nil {
		log.WithFields(logrus.Fields{
			"domain": chain.Domain,
		}).Warning("Didi not receive server/ leaf certificate")
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

	log.WithFields(logrus.Fields{
		"domain":     chain.Domain,
		"map length": len(certmap),
	}).Debug("Certificate Map length")

	trustID, err := storeCertificates(certmap)

	leafID := int64(-1)

	if trustID != -1 {

		leafID, err = GetCertIDFromTrust(trustID)

		if err != nil {
			log.WithFields(logrus.Fields{
				"domain":   chain.Domain,
				"trust_id": trustID,
				"error":    err.Error(),
			}).Error("Could not fetch leaf cert id")
		}
	}

	return leafID, trustID, err
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
			log.WithFields(logrus.Fields{
				"trust chain no":  i,
				"number of certs": len(ch),
			}).Debug("domain: " + domain)
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
			log.WithFields(logrus.Fields{
				"domain": domain,
			}).Warning("Got validation error but chains are populated")
		}

		valInfo.ValidationError = err.Error()
		valInfo.IsValid = false

		parentSignature := ""
		c := getFirstParent(serverCert, intermediates)

		if c != nil {
			parentSignature = SHA256Hash(c.Raw)
		} else {
			log.WithFields(logrus.Fields{
				"domain":     domain,
				"servercert": SHA256Hash(serverCert.Raw),
			}).Info("Could not get parent")
		}

		updateCert(serverCert, parentSignature, domain, IP, curTS.Name, valInfo, certmap)

		return false
	}

}

func storeCertificates(m map[string]Stored) (int64, error) {

	var leafTrust int64
	leafTrust = -1
	for _, c := range m {

		certID, err := GetCertIDWithSHA256Fingerprint(c.Certificate.Hashes.SHA256)

		if err != nil {
			log.WithFields(logrus.Fields{
				"domain":      c.Certificate.ScanTarget,
				"certificate": c.Certificate.Hashes.SHA256,
				"error":       err.Error(),
			}).Error("Could not get cert id from db")
		}

		if certID == -1 {
			certID, err = InsertCertificatetoDB(&c.Certificate)
			if err != nil {
				log.WithFields(logrus.Fields{
					"domain":      c.Certificate.ScanTarget,
					"certificate": c.Certificate.Hashes.SHA256,
					"error":       err.Error(),
				}).Error("Could not insert cert to db")
				continue
			} else {

				log.WithFields(logrus.Fields{
					"domain":      c.Certificate.ScanTarget,
					"certificate": c.Certificate.Hashes.SHA256,
				}).Debug("Inserted cert to db")
			}
		} else {
			UpdateCertLastSeenWithID(certID)
		}

		for _, p := range c.Certificate.ParentSignature {

			parID, err := GetCertIDWithSHA256Fingerprint(p)

			if err != nil {
				log.WithFields(logrus.Fields{
					"domain":      c.Certificate.ScanTarget,
					"certificate": c.Certificate.Hashes.SHA256,
					"parent":      p,
					"error":       err.Error(),
				}).Error("Could not get cert id for parent from db")
			}

			if parID == -1 {

				parent, ok := m[p]
				if !ok {

					log.WithFields(logrus.Fields{
						"domain":      c.Certificate.ScanTarget,
						"certificate": c.Certificate.Hashes.SHA256,
						"parent":      p,
					}).Warning("Parent not found in chain")
					continue
				}
				parID, err = InsertCertificatetoDB(&parent.Certificate)
				if err != nil {
					log.WithFields(logrus.Fields{
						"domain":      c.Certificate.ScanTarget,
						"certificate": parent.Certificate.Hashes.SHA256,
						"error":       err.Error(),
					}).Error("Could not store cert to db")
					continue
				} else {
					log.WithFields(logrus.Fields{
						"domain":      c.Certificate.ScanTarget,
						"certificate": c.Certificate.Hashes.SHA256,
					}).Debug("Inserted cert")
				}
			} else {
				UpdateCertLastSeenWithID(parID)
			}

			trustID, err := getCurrentTrust(certID, parID)

			if err != nil {
				log.WithFields(logrus.Fields{
					"domain":      c.Certificate.ScanTarget,
					"certificate": c.Certificate.Hashes.SHA256,
					"parent":      p,
					"error":       err.Error(),
				}).Error("Could not get trust for certs")
				continue
			}

			if trustID == -1 {

				trustID, err = insertTrustToDB(c.Certificate, certID, parID)
				if err != nil {
					log.WithFields(logrus.Fields{
						"domain":      c.Certificate.ScanTarget,
						"certificate": c.Certificate.Hashes.SHA256,
						"parent":      p,
						"error":       err.Error(),
					}).Error("Could not store trust for certs")
				} else {
					log.WithFields(logrus.Fields{
						"domain":      c.Certificate.ScanTarget,
						"certificate": c.Certificate.Hashes.SHA256,
						"parent":      p,
					}).Debug("Stored trust for certs")
				}
			} else {
				trustID, err = updateTrust(trustID, c.Certificate)
				if err != nil {

					log.WithFields(logrus.Fields{
						"domain":      c.Certificate.ScanTarget,
						"certificate": c.Certificate.Hashes.SHA256,
						"parent":      p,
						"error":       err.Error(),
					}).Error("Could not update trust for certs")
					log.Println("Could not update trust for certs, ", err.Error())
				} else {
					log.WithFields(logrus.Fields{
						"domain":      c.Certificate.ScanTarget,
						"certificate": c.Certificate.Hashes.SHA256,
						"parent":      p,
					}).Debug("Updated trust for certs")
				}
			}

			if !c.Certificate.CA && leafTrust == -1 {
				leafTrust = trustID
			}
		}
	}

	return leafTrust, nil

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

				log.WithFields(logrus.Fields{
					"domain":       storedCert.ScanTarget,
					"domain_input": domain,
					"certificate":  storedCert.Hashes.SHA256,
				}).Warning("Different domain input")
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
