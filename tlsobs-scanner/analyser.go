package main

import (
	// stdlib packages
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io/ioutil"

	"github.com/Sirupsen/logrus"

	"github.com/mozilla/tls-observatory/certificate"
	"github.com/mozilla/tls-observatory/config"
)

var trustStores []certificate.TrustStore
var allowedTruststoreNames = []string{certificate.Ubuntu_TS_name, certificate.Mozilla_TS_name, certificate.Microsoft_TS_name, certificate.Apple_TS_name, certificate.Android_TS_name}

func Setup(c config.Config) {
	ts := c.TrustStores

	for _, tsName := range allowedTruststoreNames {

		path := ""

		switch tsName {
		case certificate.Ubuntu_TS_name:
			path = ts.UbuntuTS
		case certificate.Mozilla_TS_name:
			path = ts.MozillaTS
		case certificate.Microsoft_TS_name:
			path = ts.MicrosoftTS
		case certificate.Apple_TS_name:
			path = ts.AppleTS
		case certificate.Android_TS_name:
			path = ts.AndroidTS
		default:
			log.WithFields(logrus.Fields{
				"tsname": tsName,
			}).Warning("Invalid Truststore name.")
		}

		log.WithFields(logrus.Fields{
			"tsname": tsName,
			"path":   path,
		}).Debug("Loading Truststore")

		// load the entire trustore into pooldata, then iterate over each PEM block
		// until all of pooldata is read
		poolData, err := ioutil.ReadFile(path)
		if err != nil {
			log.WithFields(logrus.Fields{
				"tsname": tsName,
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
					"tsname":  tsName,
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

			if !cert.IsCA {
				log.WithFields(logrus.Fields{
					"tsname":  tsName,
					"cert no": poollen + 1,
					"SHA1":    certificate.SHA1Hash(cert.Raw),
				}).Warning("Certificate in truststore is not a CA cert")
			}

			certPool.AddCert(cert)

			//Push current certificate to DB as trusted
			v := &certificate.ValidationInfo{}
			v.IsValid = true

			parentSignature := ""
			if cert.Subject.CommonName == cert.Issuer.CommonName {
				parentSignature = certificate.SHA256Hash(cert.Raw)
			}

			var id int64
			id = -1
			id, err = db.GetCertIDBySHA256Fingerprint(certificate.SHA256Hash(cert.Raw))

			if err != nil {

				log.WithFields(logrus.Fields{
					"tsname":      tsName,
					"certificate": certificate.SHA256Hash(cert.Raw),
					"error":       err.Error(),
				}).Error("Could not check if certificate is in db")
			}

			if id == -1 {

				vinfo := &certificate.ValidationInfo{}
				vinfo.IsValid = true
				vinfo.ValidationError = ""

				st := certificate.CertToStored(cert, parentSignature, "", "", tsName, vinfo)
				id, err = db.InsertCACertificatetoDB(&st, tsName)

				if err != nil {
					log.WithFields(logrus.Fields{
						"tsname":      tsName,
						"certificate": certificate.SHA256Hash(cert.Raw),
						"error":       err.Error(),
					}).Error("Could not insert certificate in db")
				}
			} else {
				db.UpdateCACertTruststore(id, tsName)
			}

			poollen++
		}
		trustStores = append(trustStores, certificate.TrustStore{tsName, certPool})
		log.WithFields(logrus.Fields{
			"tsname":              tsName,
			"certificates loaded": poollen,
		}).Info("Successfully loaded TS ")
	}

	if len(trustStores) == 0 {
		log.Error("No truststores loaded, TLS certificate retrieval & analysis won't be available")
	}
}

//handleCertChain takes the chain retrieved from the queue and tries to validate it
//against each of the truststores provided.
func handleCertChain(chain *certificate.Chain) (int64, int64, error) {

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
			if leafCert != nil {
				log.WithFields(logrus.Fields{
					"domain":           chain.Domain,
					"cert no":          chaincertno,
					"cert fingerprint": certificate.SHA256Hash(cert.Raw),
				}).Warning("Second non CA cert in chain received from server. Just add it to intermediates.")
				if cert.Version < 3 {
					log.WithFields(logrus.Fields{
						"domain":           chain.Domain,
						"cert no":          chaincertno,
						"cert fingerprint": certificate.SHA256Hash(cert.Raw),
					}).Debug("Probably an old root CA cert")
					intermediates = append(intermediates, cert)
				}
			} else {
				leafCert = cert
			}
		} else {
			intermediates = append(intermediates, cert)
		}
	}

	if leafCert == nil {
		log.WithFields(logrus.Fields{
			"domain": chain.Domain,
		}).Warning("Didi not receive server/ leaf certificate")
	}

	var certmap = make(map[string]certificate.Certificate)

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

		leafID, err = db.GetCertIDFromTrust(trustID)

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
func isChainValid(serverCert *x509.Certificate, intermediates []*x509.Certificate, curTS *certificate.TrustStore, domain, IP string, certmap map[string]certificate.Certificate) bool {

	valInfo := &certificate.ValidationInfo{}

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
					parentSignature = certificate.SHA256Hash(c.Raw)
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
			parentSignature = certificate.SHA256Hash(c.Raw)
		} else {
			log.WithFields(logrus.Fields{
				"domain":     domain,
				"servercert": certificate.SHA256Hash(serverCert.Raw),
			}).Info("Could not get parent")
		}

		updateCert(serverCert, parentSignature, domain, IP, curTS.Name, valInfo, certmap)

		return false
	}

}

func storeCertificates(m map[string]certificate.Certificate) (int64, error) {

	var leafTrust int64
	leafTrust = -1
	for _, c := range m {

		certID, err := db.GetCertIDBySHA256Fingerprint(c.Hashes.SHA256)

		if err != nil {
			log.WithFields(logrus.Fields{
				"domain":      c.ScanTarget,
				"certificate": c.Hashes.SHA256,
				"error":       err.Error(),
			}).Error("Could not get cert id from db")
		}

		// certificate does not yet exist in DB
		if certID == -1 {
			certID, err = db.InsertCertificatetoDB(&c)
			if err != nil {
				log.WithFields(logrus.Fields{
					"domain":      c.ScanTarget,
					"certificate": c.Hashes.SHA256,
					"error":       err.Error(),
				}).Error("Could not insert cert to db")
				continue
			} else {

				log.WithFields(logrus.Fields{
					"domain":      c.ScanTarget,
					"certificate": c.Hashes.SHA256,
				}).Debug("Inserted cert to db")
			}
		} else {
			db.UpdateCertLastSeenByID(certID)
		}

		for _, p := range c.ParentSignature {

			parID, err := db.GetCertIDBySHA256Fingerprint(p)

			if err != nil {
				log.WithFields(logrus.Fields{
					"domain":      c.ScanTarget,
					"certificate": c.Hashes.SHA256,
					"parent":      p,
					"error":       err.Error(),
				}).Error("Could not get cert id for parent from db")
			}

			if parID == -1 {

				parent, ok := m[p]
				if !ok {

					log.WithFields(logrus.Fields{
						"domain":      c.ScanTarget,
						"certificate": c.Hashes.SHA256,
						"parent":      p,
					}).Warning("Parent not found in chain")
					continue
				}
				parID, err = db.InsertCertificatetoDB(&parent)
				if err != nil {
					log.WithFields(logrus.Fields{
						"domain":      c.ScanTarget,
						"certificate": parent.Hashes.SHA256,
						"error":       err.Error(),
					}).Error("Could not store cert to db")
					continue
				} else {
					log.WithFields(logrus.Fields{
						"domain":      c.ScanTarget,
						"certificate": c.Hashes.SHA256,
					}).Debug("Inserted cert")
				}
			} else {
				db.UpdateCertLastSeenByID(parID)
			}

			trustID, err := db.GetCurrentTrustID(certID, parID)

			if err != nil {
				log.WithFields(logrus.Fields{
					"domain":      c.ScanTarget,
					"certificate": c.Hashes.SHA256,
					"parent":      p,
					"error":       err.Error(),
				}).Error("Could not get trust for certs")
				continue
			}

			if trustID == -1 {

				trustID, err = db.InsertTrustToDB(c, certID, parID)
				if err != nil {
					log.WithFields(logrus.Fields{
						"domain":      c.ScanTarget,
						"certificate": c.Hashes.SHA256,
						"parent":      p,
						"error":       err.Error(),
					}).Error("Could not store trust for certs")
				} else {
					log.WithFields(logrus.Fields{
						"domain":      c.ScanTarget,
						"certificate": c.Hashes.SHA256,
						"parent":      p,
					}).Debug("Stored trust for certs")
				}
			} else {
				trustID, err = db.UpdateTrust(trustID, c)
				if err != nil {

					log.WithFields(logrus.Fields{
						"domain":      c.ScanTarget,
						"certificate": c.Hashes.SHA256,
						"parent":      p,
						"error":       err.Error(),
					}).Error("Could not update trust for certs")
					log.Println("Could not update trust for certs, ", err.Error())
				} else {
					log.WithFields(logrus.Fields{
						"domain":      c.ScanTarget,
						"certificate": c.Hashes.SHA256,
						"parent":      p,
					}).Debug("Updated trust for certs")
				}
			}

			if !c.CA && leafTrust == -1 {
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
func updateCert(cert *x509.Certificate, parentSignature string, domain, ip, TSName string, valInfo *certificate.ValidationInfo, certmap map[string]certificate.Certificate) {

	id := certificate.SHA256Hash(cert.Raw)

	if storedCert, ok := certmap[id]; !ok {

		certmap[id] = certificate.CertToStored(cert, parentSignature, domain, ip, TSName, valInfo)

	} else {

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

		certmap[id] = storedCert
	}

}
