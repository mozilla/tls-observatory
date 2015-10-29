package certificate

import (
	"database/sql"
	pg "github.com/mozilla/TLS-Observer/modules/postgresmodule"
	"time"
)

var db *pg.DB

func InsertCertificatetoDB(cert *Certificate) (int64, error) {

	var id int64

	err := db.QueryRow(`INSERT INTO certificates(  sha1_fingerprint, sha256_fingerprint,
	issuer, subject, version, is_ca, valid_not_before, valid_not_after,
	first_seen, last_seen, x509_basicConstraints, x509_crlDistPoints, x509_extendedKeyUsage
	x509_authorityKeyIdentifier, x509_subjectKeyIdentifier, x509_keyUsage, x509_subjectAltName,
	signature_algo, parent_id, raw_cert ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11
	$12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24 RETURNING id )`,
		cert.Hashes.SHA1, cert.Hashes.SHA256, cert.Issuer.CommonName, cert.Subject.CommonName,
		cert.Version, cert.CA, cert.Validity.NotBefore, cert.Validity.NotAfter, cert.FirstSeenTimestamp,
		cert.LastSeenTimestamp, cert.X509v3BasicConstraints, cert.X509v3Extensions.CRLDistributionPoints,
		cert.X509v3Extensions.ExtendedKeyUsage, cert.X509v3Extensions.AuthorityKeyId,
		cert.X509v3Extensions.SubjectKeyId, cert.X509v3Extensions.KeyUsage,
		cert.X509v3Extensions.SubjectAlternativeName, cert.SignatureAlgorithm,
		cert.ParentSignature, cert.Raw).Scan(&id)

	if err != nil {
		return -1, err
	}

	return id, nil
}

func UpdateCertLastSeen(cert *Certificate) error {

	_, err := db.Exec("UPDATE certificates SET last_seen=$1 WHERE sha1_fingerprint=$2", cert.LastSeenTimestamp, cert.Hashes.SHA1)
	return err
}

func GetCertID(sha1 string) (int64, error) {

	row := db.QueryRow(`SELECT id FROM certificates	WHERE sha1_fingerprint=$1`, sha1)

	var id int64

	err := row.Scan(&id)

	if err != nil {
		return -1, nil
	} else {
		return id, nil
	}
}

func GetCertwithFingerprint(sha1 string) (*Certificate, error) {

	row := db.QueryRow(`SELECT sha256_fingerprint,
		issuer, subject, version, is_ca, valid_not_before, valid_not_after, 
		first_seen, last_Seen, x509_basicConstraints, x509_crlDistPoints, x509_extendedKeyUsage
		x509_authorityKeyIdentifier, x509_subjectKeyIdentifier, x509_keyUsage, x509_subjectAltName,
		signature_algo, parent_id, raw_cert
		FROM certificates
		WHERE sha1_fingerprint=$1`, sha1)

	cert := &Certificate{}

	err := row.Scan(&cert.Hashes.SHA256, &cert.Issuer.CommonName, &cert.Subject.CommonName,
		&cert.Version, &cert.CA, &cert.Validity.NotBefore, &cert.Validity.NotAfter, &cert.FirstSeenTimestamp,
		&cert.LastSeenTimestamp, &cert.X509v3BasicConstraints, &cert.X509v3Extensions.CRLDistributionPoints,
		&cert.X509v3Extensions.ExtendedKeyUsage, &cert.X509v3Extensions.AuthorityKeyId,
		&cert.X509v3Extensions.SubjectKeyId, &cert.X509v3Extensions.KeyUsage,
		&cert.X509v3Extensions.SubjectAlternativeName, &cert.SignatureAlgorithm,
		&cert.ParentSignature)

	if err != nil {
		return nil, err
	} else {
		return cert, nil
	}

}

func GetCertwithID(id string) (*Certificate, error) {

	row := db.QueryRow(`SELECT sha1_fingerprint,sha256_fingerprint,
		issuer, subject, version, is_ca, valid_not_before, valid_not_after, 
		first_seen, last_Seen, x509_basicConstraints, x509_crlDistPoints, x509_extendedKeyUsage
		x509_authorityKeyIdentifier, x509_subjectKeyIdentifier, x509_keyUsage, x509_subjectAltName,
		signature_algo, parent_id, raw_cert
		FROM certificates
		WHERE id=$1`, id)

	cert := &Certificate{}

	err := row.Scan(&cert.Hashes.SHA1, &cert.Hashes.SHA256, &cert.Issuer.CommonName, &cert.Subject.CommonName,
		&cert.Version, &cert.CA, &cert.Validity.NotBefore, &cert.Validity.NotAfter, &cert.FirstSeenTimestamp,
		&cert.LastSeenTimestamp, &cert.X509v3BasicConstraints, &cert.X509v3Extensions.CRLDistributionPoints,
		&cert.X509v3Extensions.ExtendedKeyUsage, &cert.X509v3Extensions.AuthorityKeyId,
		&cert.X509v3Extensions.SubjectKeyId, &cert.X509v3Extensions.KeyUsage,
		&cert.X509v3Extensions.SubjectAlternativeName, &cert.SignatureAlgorithm,
		&cert.ParentSignature)

	if err != nil {
		return nil, err
	} else {
		return cert, nil
	}

}

func insertTrustToDB(cert Certificate, certID, parID int64) (int64, error) {

	var trustID int64

	var trusted_ubuntu, trusted_mozilla, trusted_microsoft, trusted_apple, trusted_android bool

	err := db.QueryRow(`INSERT INTO trust(cert_id,issuer_id,timestamp,trusted_ubuntu,trusted_mozilla,trusted_microsoft,trusted_apple,trusted_android,is_current)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, certID, parID, time.Now(), trusted_ubuntu, trusted_mozilla, trusted_microsoft, trusted_apple, trusted_android, true).Scan(&trustID)

	if err != nil {
		return -1, err
	}

	return trustID, nil

}

func updateTrust(trustID int64, cert Certificate) (int64, error) {

	var trusted_ubuntu, trusted_mozilla, trusted_microsoft, trusted_apple, trusted_android bool

	err := db.QueryRow(`SELECT (certificate_id, issuer_id, trusted_ubuntu, trusted_mozilla, trusted_microsoft, trusted_apple, trusted_android) FROM trust WHERE id=$1`,
		trustID).Scan(&trusted_ubuntu, &trusted_mozilla, &trusted_microsoft, &trusted_apple, &trusted_android)

	if err != nil {
		return -1, err
	}

	return trustID, nil

}

func getTrust(certID, issuerID int64) (int64, error) {

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
