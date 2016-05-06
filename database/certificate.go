package database

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/mozilla/tls-observatory/certificate"
)

// InsertCertificatetoDB inserts a x509 certificate to the database.
// It takes as input a Certificate pointer.
// It returns the database ID of the inserted certificate ( -1 if an error occures ) and an error, if it occures.
func (db *DB) InsertCertificatetoDB(cert *certificate.Certificate) (int64, error) {

	var id int64

	crl_dist_points, err := json.Marshal(cert.X509v3Extensions.CRLDistributionPoints)
	if err != nil {
		return -1, err
	}

	extkeyusage, err := json.Marshal(cert.X509v3Extensions.ExtendedKeyUsage)
	if err != nil {
		return -1, err
	}

	keyusage, err := json.Marshal(cert.X509v3Extensions.KeyUsage)
	if err != nil {
		return -1, err
	}

	subaltname, err := json.Marshal(cert.X509v3Extensions.SubjectAlternativeName)
	if err != nil {
		return -1, err
	}

	issuer, err := json.Marshal(cert.Issuer)
	if err != nil {
		return -1, err
	}

	subject, err := json.Marshal(cert.Subject)
	if err != nil {
		return -1, err
	}

	key, err := json.Marshal(cert.Key)
	if err != nil {
		return -1, err
	}

	domainstr := ""

	if !cert.CA {
		domainfound := false
		for _, d := range cert.X509v3Extensions.SubjectAlternativeName {
			if d == cert.Subject.CommonName {
				domainfound = true
			}
		}

		var domains []string

		if !domainfound {
			domains = append(cert.X509v3Extensions.SubjectAlternativeName, cert.Subject.CommonName)
		} else {
			domains = cert.X509v3Extensions.SubjectAlternativeName
		}

		domainstr = strings.Join(domains, ",")
	}

	err = db.QueryRow(`INSERT INTO certificates(
					sha1_fingerprint, sha256_fingerprint,
					issuer,
					subject,
					version,
					is_ca,
					not_valid_before, not_valid_after,
					first_seen, last_seen,
					key_alg, key,
					x509_basicConstraints,
					x509_crlDistributionPoints,
					x509_extendedKeyUsage,
					x509_authorityKeyIdentifier,
					x509_subjectKeyIdentifier,
					x509_keyUsage,
					x509_subjectAltName,
					signature_algo,
					domains,
					raw_cert
					) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11,
					$12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22) RETURNING id`,
		cert.Hashes.SHA1, cert.Hashes.SHA256,
		issuer,
		subject,
		cert.Version,
		cert.CA,
		cert.Validity.NotBefore, cert.Validity.NotAfter,
		time.Now(), time.Now(),
		cert.Key.Alg, key,
		cert.X509v3BasicConstraints,
		crl_dist_points,
		extkeyusage,
		cert.X509v3Extensions.AuthorityKeyId,
		cert.X509v3Extensions.SubjectKeyId,
		keyusage,
		subaltname,
		cert.SignatureAlgorithm,
		domainstr,
		cert.Raw,
	).Scan(&id)
	if err != nil {
		return -1, err
	}
	return id, nil
}

// InsertCACertificatetoDB inserts a x509 certificate imported from a truststore to the database.
// It takes as input a Certificate pointer and the name of the imported trust store.
// It does a "dumb" translation from trust store name to mapped certificate table variables.
// It returns the database ID of the inserted certificate ( -1 if an error occures ) and an error, if it occures.
func (db *DB) InsertCACertificatetoDB(cert *certificate.Certificate, tsName string) (int64, error) {

	var id int64

	crl_dist_points, err := json.Marshal(cert.X509v3Extensions.CRLDistributionPoints)

	if err != nil {
		return -1, err
	}

	extkeyusage, err := json.Marshal(cert.X509v3Extensions.ExtendedKeyUsage)

	if err != nil {
		return -1, err
	}

	keyusage, err := json.Marshal(cert.X509v3Extensions.KeyUsage)

	if err != nil {
		return -1, err
	}

	subaltname, err := json.Marshal(cert.X509v3Extensions.SubjectAlternativeName)

	if err != nil {
		return -1, err
	}

	issuer, err := json.Marshal(cert.Issuer)
	if err != nil {
		return -1, err
	}

	subject, err := json.Marshal(cert.Subject)
	if err != nil {
		return -1, err
	}

	key, err := json.Marshal(cert.Key)
	if err != nil {
		return -1, err
	}

	tsVariable := ""
	switch tsName {
	case certificate.Ubuntu_TS_name:
		tsVariable = "in_ubuntu_root_store"
	case certificate.Mozilla_TS_name:
		tsVariable = "in_mozilla_root_store"
	case certificate.Microsoft_TS_name:
		tsVariable = "in_microsoft_root_store"
	case certificate.Apple_TS_name:
		tsVariable = "in_apple_root_store"
	case certificate.Android_TS_name:
		tsVariable = "in_android_root_store"
	default:
		return -1, errors.New(fmt.Sprintf("Cannot insert to DB, %s does not represent a valid truststore name.", tsName))
	}

	queryStr := fmt.Sprintf(`INSERT INTO certificates(
				sha1_fingerprint, sha256_fingerprint,
				issuer,
				subject,
				version,
				is_ca,
				not_valid_before, not_valid_after,
				first_seen, last_seen,
				key_alg, key,
				x509_basicConstraints,
				x509_crlDistributionPoints,
				x509_extendedKeyUsage,
				x509_authorityKeyIdentifier,
				x509_subjectKeyIdentifier, 
				x509_keyUsage, 
				x509_subjectAltName,
				signature_algo, 
				raw_cert, %s ) VALUES ( $1,$2, $3, $4, $5, $6, $7, $8, $9, $10, $11,
				$12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22 ) RETURNING id`,
		tsVariable)

	err = db.QueryRow(queryStr,
		cert.Hashes.SHA1, cert.Hashes.SHA256,
		issuer,
		subject,
		cert.Version,
		cert.CA,
		cert.Validity.NotBefore, cert.Validity.NotAfter,
		time.Now(), time.Now(),
		cert.Key.Alg, key,
		cert.X509v3BasicConstraints,
		crl_dist_points,
		extkeyusage,
		cert.X509v3Extensions.AuthorityKeyId,
		cert.X509v3Extensions.SubjectKeyId,
		keyusage,
		subaltname,
		cert.SignatureAlgorithm,
		cert.Raw,
		true).Scan(&id)
	if err != nil {
		return -1, err
	}
	return id, nil
}

// UpdateCertLastSeen updates the last_seen timestamp of the input certificate.
// Outputs an error if it occurs.
func (db *DB) UpdateCertLastSeen(cert *certificate.Certificate) error {

	_, err := db.Exec("UPDATE certificates SET last_seen=$1 WHERE sha1_fingerprint=$2", cert.LastSeenTimestamp, cert.Hashes.SHA1)
	return err
}

// UpdateCertLastSeenWithID updates the last_seen timestamp of the certificate with the given id.
// Outputs an error if it occurs.
func (db *DB) UpdateCertLastSeenByID(id int64) error {

	_, err := db.Exec("UPDATE certificates SET last_seen=$1 WHERE id=$2", time.Now(), id)
	return err
}

// UpdateCACertTruststore updates the last_seen timestamp and the in_xxx_root_store variables of the certificate with the given id.
// It takes as input a certificate id and the name of the imported trust store.
// It does a "dumb" translation from trust store name to mapped certificate table variables.
// Outputs an error if any occur.
func (db *DB) UpdateCACertTruststore(id int64, tsName string) error {

	tsVariable := ""
	switch tsName {
	case certificate.Ubuntu_TS_name:
		tsVariable = "in_ubuntu_root_store"
	case certificate.Mozilla_TS_name:
		tsVariable = "in_mozilla_root_store"
	case certificate.Microsoft_TS_name:
		tsVariable = "in_microsoft_root_store"
	case certificate.Apple_TS_name:
		tsVariable = "in_apple_root_store"
	case certificate.Android_TS_name:
		tsVariable = "in_android_root_store"
	default:
		return errors.New(fmt.Sprintf("Cannot update DB, %s does not represent a valid truststore name.", tsName))
	}

	queryStr := fmt.Sprintf("UPDATE certificates SET %s=$1,last_seen=$2 WHERE id=$3", tsVariable)

	_, err := db.Exec(queryStr, true, time.Now(), id)
	return err
}

// GetCertIDWithSHA1Fingerprint fetches the database id of the certificate with the given SHA1 fingerprint.
// Returns the mentioned id and any errors that happen.
// It wraps the sql.ErrNoRows error in order to avoid passing not existing row errors to upper levels.
// In that case it returns -1 with no error.
func (db *DB) GetCertIDBySHA1Fingerprint(sha1 string) (int64, error) {

	query := fmt.Sprintf(`SELECT id FROM certificates WHERE sha1_fingerprint='%s' ORDER BY id ASC LIMIT 1`, sha1)

	row := db.QueryRow(query)

	var id int64

	err := row.Scan(&id)

	if err != nil {
		if err == sql.ErrNoRows {
			return -1, nil
		} else {
			return -1, err
		}
	} else {
		return id, nil
	}
}

// GetCertIDWithSHA256Fingerprint fetches the database id of the certificate with the given SHA256 fingerprint.
// Returns the mentioned id and any errors that happen.
// It wraps the sql.ErrNoRows error in order to avoid passing not existing row errors to upper levels.
// In that case it returns -1 with no error.
func (db *DB) GetCertIDBySHA256Fingerprint(sha256 string) (int64, error) {

	query := fmt.Sprintf(`SELECT id FROM certificates WHERE sha256_fingerprint='%s' ORDER BY id ASC LIMIT 1`, sha256)

	row := db.QueryRow(query)

	var id int64

	err := row.Scan(&id)

	if err != nil {
		if err == sql.ErrNoRows {
			return -1, nil
		} else {
			return -1, err
		}
	} else {
		return id, nil
	}
}

// GetCertIDFromTrust fetches the database id of the certificate in the trust relation with the given id.
// Returns the mentioned id and any errors that happen.
// It wraps the sql.ErrNoRows error in order to avoid passing not existing row errors to upper levels.
// In that case it returns -1 with no error.
func (db *DB) GetCertIDFromTrust(trustID int64) (int64, error) {

	row := db.QueryRow("SELECT cert_id FROM trust WHERE id=$1", trustID)

	var id int64

	err := row.Scan(&id)

	if err != nil {
		if err == sql.ErrNoRows {
			return -1, nil
		} else {
			return -1, err
		}
	} else {
		return id, nil
	}

}

// GetCertBySHA1Fingerprint fetches a certain certificate from the database.
// It returns a pointer to a Certificate struct and any errors that occur.
func (db *DB) GetCertBySHA1Fingerprint(sha1 string) (*certificate.Certificate, error) {

	row := db.QueryRow(`SELECT id, sha1_fingerprint, sha256_fingerprint,
	issuer, subject, version, is_ca, not_valid_before, not_valid_after,
	first_seen, last_seen, x509_basicConstraints, x509_crlDistributionPoints, x509_extendedKeyUsage,
	x509_authorityKeyIdentifier, x509_subjectKeyIdentifier, x509_keyUsage, x509_subjectAltName,
	signature_algo, raw_cert
	FROM certificates
	WHERE sha1_fingerprint=$1`, sha1)

	cert := &certificate.Certificate{}

	var certID int64

	var crl_dist_points, extkeyusage, keyusage, subaltname, issuer, subject []byte

	err := row.Scan(&certID, &cert.Hashes.SHA1, &cert.Hashes.SHA256, &issuer, &subject,
		&cert.Version, &cert.CA, &cert.Validity.NotBefore, &cert.Validity.NotAfter, &cert.FirstSeenTimestamp,
		&cert.LastSeenTimestamp, &cert.X509v3BasicConstraints, &crl_dist_points, &extkeyusage, &cert.X509v3Extensions.AuthorityKeyId,
		&cert.X509v3Extensions.SubjectKeyId, &keyusage, &subaltname, &cert.SignatureAlgorithm, &cert.Raw)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(crl_dist_points, &cert.X509v3Extensions.CRLDistributionPoints)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(extkeyusage, cert.X509v3Extensions.ExtendedKeyUsage)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(keyusage, cert.X509v3Extensions.KeyUsage)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(subaltname, cert.X509v3Extensions.SubjectAlternativeName)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(issuer, &cert.Issuer)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(subject, &cert.Subject)
	if err != nil {
		return nil, err
	}

	cert.ValidationInfo, err = db.GetValidationMapForCert(certID)

	return cert, err
}

// GetCertByID fetches a certain certificate from the database.
// It returns a pointer to a Certificate struct and any errors that occur.
func (db *DB) GetCertByID(certID int64) (*certificate.Certificate, error) {

	row := db.QueryRow(`SELECT sha1_fingerprint, sha256_fingerprint,
	issuer, subject, version, is_ca, not_valid_before, not_valid_after, key,
	first_seen, last_seen, x509_basicConstraints, x509_crlDistributionPoints, x509_extendedKeyUsage,
	x509_authorityKeyIdentifier, x509_subjectKeyIdentifier, x509_keyUsage, x509_subjectAltName,
	signature_algo, raw_cert
		FROM certificates
		WHERE id=$1`, certID)

	cert := &certificate.Certificate{}

	var crl_dist_points, extkeyusage, keyusage, subaltname, issuer, subject, key []byte

	err := row.Scan(&cert.Hashes.SHA1, &cert.Hashes.SHA256, &issuer, &subject,
		&cert.Version, &cert.CA, &cert.Validity.NotBefore, &cert.Validity.NotAfter, &key, &cert.FirstSeenTimestamp,
		&cert.LastSeenTimestamp, &cert.X509v3BasicConstraints, &crl_dist_points, &extkeyusage, &cert.X509v3Extensions.AuthorityKeyId,
		&cert.X509v3Extensions.SubjectKeyId, &keyusage, &subaltname, &cert.SignatureAlgorithm, &cert.Raw)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(crl_dist_points, &cert.X509v3Extensions.CRLDistributionPoints)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(extkeyusage, &cert.X509v3Extensions.ExtendedKeyUsage)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(keyusage, &cert.X509v3Extensions.KeyUsage)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(subaltname, &cert.X509v3Extensions.SubjectAlternativeName)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(issuer, &cert.Issuer)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(subject, &cert.Subject)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(key, &cert.Key)
	if err != nil {
		return nil, err
	}

	cert.ValidationInfo, err = db.GetValidationMapForCert(certID)

	return cert, err

}

func (db *DB) InsertTrustToDB(cert certificate.Certificate, certID, parID int64) (int64, error) {

	var trustID int64

	trusted_ubuntu, trusted_mozilla, trusted_microsoft, trusted_apple, trusted_android := cert.GetBooleanValidity()

	err := db.QueryRow(`INSERT INTO trust(cert_id,issuer_id,timestamp,trusted_ubuntu,trusted_mozilla,trusted_microsoft,trusted_apple,trusted_android,is_current)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id`, certID, parID, time.Now(), trusted_ubuntu, trusted_mozilla, trusted_microsoft, trusted_apple, trusted_android, true).Scan(&trustID)

	if err != nil {
		return -1, err
	}

	return trustID, nil

}

func (db *DB) UpdateTrust(trustID int64, cert certificate.Certificate) (int64, error) {

	var trusted_ubuntu, trusted_mozilla, trusted_microsoft, trusted_apple, trusted_android bool

	var certID, parID int64

	err := db.QueryRow(`SELECT cert_id, issuer_id, trusted_ubuntu, trusted_mozilla, trusted_microsoft, trusted_apple, trusted_android FROM trust WHERE id=$1 AND is_current=TRUE`,
		trustID).Scan(&certID, &parID, &trusted_ubuntu, &trusted_mozilla, &trusted_microsoft, &trusted_apple, &trusted_android)

	if err != nil {
		return -1, err
	}

	new_ubuntu, new_mozilla, new_microsoft, new_apple, new_android := cert.GetBooleanValidity()

	isTrustCurrent := true

	if trusted_ubuntu != new_ubuntu || trusted_mozilla != new_mozilla || trusted_microsoft != new_microsoft || trusted_apple != new_apple || trusted_android != new_android {
		isTrustCurrent = false
	}

	if !isTrustCurrent { // create new trust and obsolete old one

		newID, err := db.InsertTrustToDB(cert, certID, parID)

		if err != nil {
			return -1, err
		}

		_, err = db.Exec("UPDATE trust SET is_current=$1 WHERE id=$2", false, trustID)

		if err != nil {
			return -1, err
		}

		return newID, nil

	} else { //update current timestamp

		_, err = db.Exec("UPDATE trust SET timestamp=$1 WHERE id=$2", time.Now(), trustID)

		return trustID, err

	}
}

func (db *DB) GetCurrentTrustID(certID, issuerID int64) (int64, error) {

	var trustID int64

	row := db.QueryRow("SELECT id FROM trust WHERE cert_id=$1 AND issuer_id=$2 AND is_current=TRUE", certID, issuerID)

	err := row.Scan(&trustID)

	if err != nil {

		if err == sql.ErrNoRows {
			return -1, nil
		} else {
			return -1, err
		}
	}

	return trustID, nil
}

func (db *DB) GetCurrentTrustIDForCert(certID int64) (int64, error) {

	var trustID int64

	row := db.QueryRow("SELECT id FROM trust WHERE cert_id=$1 AND is_current=TRUE", certID)

	err := row.Scan(&trustID)

	if err != nil {

		if err == sql.ErrNoRows {
			return -1, nil
		} else {
			return -1, err
		}
	}

	return trustID, nil
}

func (db *DB) GetValidationMapForCert(certID int64) (map[string]certificate.ValidationInfo, error) {

	var ubuntu, mozilla, microsoft, apple, android bool
	m := make(map[string]certificate.ValidationInfo)
	row := db.QueryRow("SELECT trusted_ubuntu,trusted_mozilla,trusted_microsoft,trusted_apple,trusted_android FROM trust WHERE cert_id=$1 AND is_current=TRUE", certID)

	err := row.Scan(&ubuntu, &mozilla, &microsoft, &apple, &android)

	if err != nil {

		if err == sql.ErrNoRows {
			return m, nil
		} else {
			return m, err
		}
	}

	return certificate.GetValidityMap(ubuntu, mozilla, microsoft, apple, android), nil
}

// IsTrustValid returns the validity of the trust relationship for the given id.
// It returns a "valid" if any of the per truststore valitities is valid
// It returns a boolean that represent if trust is valid or not.
func (db *DB) IsTrustValid(id int64) (bool, error) {

	row := db.QueryRow("SELECT trusted_ubuntu OR trusted_mozilla OR trusted_microsoft OR trusted_apple OR trusted_android FROM trust WHERE id=$1", id)

	var isValid bool
	isValid = false

	err := row.Scan(&isValid)

	return isValid, err
}
