package main

import (
	// stdlib packages
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io/ioutil"

	"github.com/sirupsen/logrus"

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

		// keep a list of cert hashes currently in this truststore
		// to remove certs no longer in it
		certHashes := make([]string, 0)

		for len(poolData) > 0 {
			// read the next PEM block, ignore non CERTIFICATE entries
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
			certHash := certificate.SHA256Hash(cert.Raw)
			certHashes = append(certHashes, certHash)
			parentSignature := ""
			if cert.Subject.CommonName == cert.Issuer.CommonName {
				// self-signed, parent sig is self sig
				parentSignature = certHash
			}
			var id int64 = -1
			id, err = db.GetCertIDBySHA256Fingerprint(certHash)
			if err != nil {
				log.WithFields(logrus.Fields{
					"tsname":      tsName,
					"certificate": certificate.SHA256Hash(cert.Raw),
					"error":       err.Error(),
				}).Error("Could not check if certificate is in db")
			}

			if id == -1 {
				// insert certificate for the first time
				vinfo := &certificate.ValidationInfo{}
				vinfo.IsValid = true
				vinfo.ValidationError = ""

				st := certificate.CertToStored(cert, parentSignature, "", "", tsName, vinfo)
				id, err = db.InsertCertificate(&st)
				if err != nil {
					log.WithFields(logrus.Fields{
						"certificate": certificate.SHA256Hash(cert.Raw),
						"error":       err.Error(),
					}).Error("Could not insert certificate in db")
				}
			}
			switch tsName {
			case certificate.Ubuntu_TS_name:
				err = db.AddCertToUbuntuTruststore(id)
			case certificate.Mozilla_TS_name:
				err = db.AddCertToMozillaTruststore(id)
			case certificate.Microsoft_TS_name:
				err = db.AddCertToMicrosoftTruststore(id)
			case certificate.Apple_TS_name:
				err = db.AddCertToAppleTruststore(id)
			case certificate.Android_TS_name:
				err = db.AddCertToAndroidTruststore(id)
			}
			if err != nil {
				log.WithFields(logrus.Fields{
					"tsname": tsName,
					"id":     id,
					"error":  err.Error(),
				}).Error("Could not update certificate trust in db")
			}
			poollen++
		}
		if poollen == 0 {
			log.WithFields(logrus.Fields{
				"tsname": tsName,
			}).Fatal("No CA cert found in truststore")
		}
		// We have a list of certificates in the current truststore and
		// we use it to disable certs no longer in in
		err = db.RemoveCACertFromTruststore(certHashes, tsName)
		if err != nil {
			log.WithFields(logrus.Fields{
				"tsname": tsName,
				"error":  err.Error(),
			}).Fatal("Failed to update trust of certificates no longer in truststore")
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
//against each of the truststores provided. The function returns the ID of the end
//entity certificate (or -1 if not stored), the ID of the trust entry (or -1 if not
//stored) and an error message.
func handleCertChain(chain *certificate.Chain) (int64, int64, error) {

	var intermediates []*x509.Certificate
	var endEntity *x509.Certificate
	endEntity = nil

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

		// if certificate is an authority,
		// append it to the list of intermediate certs and go to the next one
		if cert.IsCA {
			intermediates = append(intermediates, cert)
			continue
		}
		// if we don't yet have an end entity in this chain
		// set the current cert as the end entity
		if endEntity == nil {
			endEntity = cert
			continue
		}
		// here we have a cert that's an end entity when we already
		// found one in the chain. It's possible that it's an old
		// V2 cert that's actually an intermediate by doesn't have the
		// CA flag set
		log.WithFields(logrus.Fields{
			"domain":           chain.Domain,
			"cert no":          chaincertno,
			"cert fingerprint": certificate.SHA256Hash(cert.Raw),
		}).Warning("Second End Entity cert found in chain received from server. Adding it to intermediates.")
		if cert.Version < 3 {
			log.WithFields(logrus.Fields{
				"domain":           chain.Domain,
				"cert no":          chaincertno,
				"cert fingerprint": certificate.SHA256Hash(cert.Raw),
			}).Debug("Probably an old root CA cert")
			intermediates = append(intermediates, cert)
		}
	}

	if endEntity == nil {
		log.WithFields(logrus.Fields{
			"domain": chain.Domain,
		}).Warning("the certificate chain did not contain an end entity certificate")
	}

	var certmap = make(map[string]certificate.Certificate)

	// Test the end entity cert with its chain against each of the truststore
	for _, truststore := range trustStores {
		if endEntity != nil && isChainValid(endEntity, intermediates, &truststore, chain.Domain, chain.IP, certmap) {
			// If we have an end entity cert and its chain of trust is valid, our work
			// here is done, move to the next truststore
			continue
		}

		// to end up here either there was no leaf certificate retrieved
		// or it was retrieved but it was not valid so we must check the remainder of the chain
		for i, cert := range intermediates {
			inter := append(intermediates[:i], intermediates[i+1:]...)
			isChainValid(cert, inter, &truststore, chain.Domain, chain.IP, certmap)
		}
	}

	log.WithFields(logrus.Fields{
		"domain":     chain.Domain,
		"map length": len(certmap),
	}).Debug("Certificate Map length")

	return storeCertificates(certmap)
}

//isChainValid creates the valid certificate chains by combining the chain retrieved with the provided truststore.
//It return true if it finds at least on validation chain or false if no valid chain of trust can be created.
//It also updates the certificate map which gets pushed at the end of each iteration.
func isChainValid(endEntity *x509.Certificate, intermediates []*x509.Certificate, truststore *certificate.TrustStore, domain, IP string, certmap map[string]certificate.Certificate) bool {
	valInfo := &certificate.ValidationInfo{
		IsValid: true,
	}

	// build a CA verification pool from the list of cacerts
	interPool := x509.NewCertPool()
	for _, entity := range intermediates {
		interPool.AddCert(entity)
	}

	// get a list of domains this certificate is supposedly valid for
	// if the end entity is a CA, use its common name
	dnsName := domain
	if endEntity.IsCA {
		dnsName = endEntity.Subject.CommonName
	}

	// configure the verification logic to use the current trustore
	opts := x509.VerifyOptions{
		DNSName:       dnsName,
		Intermediates: interPool,
		Roots:         truststore.Certs,
	}

	// Verify attempts to build all the path between the end entity and the
	// root in the truststore that validate the certificate
	// If no valid path is found, err is not nil and the certificate is not trusted
	chains, err := endEntity.Verify(opts)

	if err == nil {
		// the end entity is trusted, we need to go through each
		// chain of trust and store them in database
		for i, chain := range chains {
			log.WithFields(logrus.Fields{
				"trust chain no": i,
				"path len":       len(chain),
			}).Debug("domain: " + domain)
			// loop through each certificate in the chain and
			for _, cert := range chain {
				parentSignature := ""
				parentCert := getFirstParent(cert, chain)
				if parentCert != nil {
					parentSignature = certificate.SHA256Hash(parentCert.Raw)
				} else {
					log.Println("could not retrieve parent for " + dnsName)
				}
				updateCert(cert, parentSignature, domain, IP, truststore.Name, valInfo, certmap)
			}
		}
		return true
	}

	// the certificate is not trusted.
	// we store the cert in DB with its validation error
	if len(chains) > 0 {
		log.WithFields(logrus.Fields{
			"domain": domain,
		}).Warning("Got validation error but chains are populated")
	}

	valInfo.ValidationError = err.Error()
	valInfo.IsValid = false

	parentSignature := ""
	c := getFirstParent(endEntity, intermediates)

	if c != nil {
		parentSignature = certificate.SHA256Hash(c.Raw)
	} else {
		log.WithFields(logrus.Fields{
			"domain":     domain,
			"servercert": certificate.SHA256Hash(endEntity.Raw),
		}).Info("Could not get parent")
	}

	updateCert(endEntity, parentSignature, domain, IP, truststore.Name, valInfo, certmap)

	return false

}

// storeCertificates loops through each certificate in a map of certs to store them in the database
// (if not yet stored) or update their last seen timestamp (if already stored).
// The same is done for the issuer of the certificate.
// Then the trust of the certificate is checked. If a trust entry already exists for this certificate
// and its issuer in database, the entry is updated. Otherwise, a new entry is created.
//
// The ID of the end entity certificate and its trust entry in database are returned, along with any error
func storeCertificates(certmap map[string]certificate.Certificate) (EECertID int64, EETrustID int64, err error) {
	EECertID, EETrustID = -1, -1

	// certIDToVisited is the set of certs we see (golang does not have a builtin set/hashset type)
	certIDToVisited := make(map[int64]bool)

	for _, cert := range certmap {
		certID, err := db.GetCertIDBySHA256Fingerprint(cert.Hashes.SHA256)
		if err != nil {
			log.WithFields(logrus.Fields{
				"domain":      cert.ScanTarget,
				"certificate": cert.Hashes.SHA256,
				"error":       err.Error(),
			}).Error("Could not get cert id from db")
		}

		// certificate does not yet exist in DB
		if certID == -1 {
			certID, err = db.InsertCertificate(&cert)
			if err != nil {
				log.WithFields(logrus.Fields{
					"domain":      cert.ScanTarget,
					"certificate": cert.Hashes.SHA256,
					"error":       err.Error(),
				}).Error("Could not insert cert to db")
				continue
			} else {

				log.WithFields(logrus.Fields{
					"domain":      cert.ScanTarget,
					"certificate": cert.Hashes.SHA256,
				}).Debug("Inserted cert to db")
			}
		} else {
			certIDToVisited[certID] = true
		}

		// If the certificate is not a CA Cert, stores its ID as the end entity
		if !cert.CA && EECertID == -1 {
			EECertID = certID
		}

		// insert the issuer of the certificate in DB (if not yet stored)
		// or update its last seen timestamp (if already stored)
		for _, issuer := range cert.ParentSignature {

			issuerID, err := db.GetCertIDBySHA256Fingerprint(issuer)
			if err != nil {
				log.WithFields(logrus.Fields{
					"domain":      cert.ScanTarget,
					"certificate": cert.Hashes.SHA256,
					"issuer":      issuer,
					"error":       err.Error(),
				}).Error("Failed to get id of issuer certificate from database")
			}

			if issuerID == -1 {
				issuer, ok := certmap[issuer]
				if !ok {
					log.WithFields(logrus.Fields{
						"domain":      cert.ScanTarget,
						"certificate": cert.Hashes.SHA256,
						"issuer":      issuerID,
					}).Warning("The issuer of the certificate was not found in the chain of trust, certificate is not trusted.")
					continue
				}
				issuerID, err = db.InsertCertificate(&issuer)
				if err != nil {
					log.WithFields(logrus.Fields{
						"domain":      cert.ScanTarget,
						"certificate": issuer.Hashes.SHA256,
						"error":       err.Error(),
					}).Error("Failed to store certificate in database")
					continue
				} else {
					log.WithFields(logrus.Fields{
						"domain":      cert.ScanTarget,
						"certificate": cert.Hashes.SHA256,
					}).Debug("Inserted issuer certificate in database")
				}
			} else {
				certIDToVisited[issuerID] = true
			}

			// check if a trust entry already exists for this certificate and its issuer.
			// If none exists, create one. Otherwise, update the existing entry.
			trustID, err := db.GetCurrentTrustID(certID, issuerID)
			if err != nil {
				log.WithFields(logrus.Fields{
					"domain":      cert.ScanTarget,
					"certificate": cert.Hashes.SHA256,
					"issuer":      issuer,
					"error":       err.Error(),
				}).Error("Could not get trust for certs")
				continue
			}

			// No trust entry exists, create one
			if trustID == -1 {
				trustID, err = db.InsertTrustToDB(cert, certID, issuerID)
				if err != nil {
					log.WithFields(logrus.Fields{
						"domain":      cert.ScanTarget,
						"certificate": cert.Hashes.SHA256,
						"issuer":      issuer,
						"error":       err.Error(),
					}).Error("Failed to store trust entry for certificate and its issuer")
				} else {
					log.WithFields(logrus.Fields{
						"domain":      cert.ScanTarget,
						"certificate": cert.Hashes.SHA256,
						"issuer":      issuer,
					}).Debug("Trust entry for cert and issuer stored in database")
				}

				// Update the existing trust entry
			} else {
				trustID, err = db.UpdateTrust(trustID, cert)
				if err != nil {
					log.WithFields(logrus.Fields{
						"domain":      cert.ScanTarget,
						"certificate": cert.Hashes.SHA256,
						"issuer":      issuer,
						"error":       err.Error(),
					}).Error("Failed to update trust entry for cert and issuer")
				} else {
					log.WithFields(logrus.Fields{
						"domain":      cert.ScanTarget,
						"certificate": cert.Hashes.SHA256,
						"issuer":      issuer,
					}).Debug("Updated trust entry for cert and issuer")
				}
			}

			// Store the trust ID of the EE cert
			if !cert.CA && certID == EECertID && EETrustID == -1 {
				EETrustID = trustID
			}
		}
	}

	// get slice of visitedCertIDs from certIDToVisited keys
	visitedCertIDs := make([]int64, len(certIDToVisited))
	i := 0
	for certID := range certIDToVisited {
		visitedCertIDs[i] = certID
		i++
	}
	db.UpdateCertsLastSeenByID(visitedCertIDs)
	return
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
