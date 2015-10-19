package postgresmodule

//using latest https://hub.docker.com/_/postgres/ image for testing

import (
	"github.com/mozilla/TLS-Observer/certificate"
)

func (db *DB) InsertCertificate(cert *certificate.Certificate) error {

	_, err := db.Exec(`INSERT INTO certificates(  sha1_fingerprint, sha256_fingerprint,
	issuer, subject, version, is_ca, valid_not_before, valid_not_after,
	first_seen, last_seen, x509_basicConstraints, x509_crlDistPoints, x509_extendedKeyUsage
	x509_authorityKeyIdentifier, x509_subjectKeyIdentifier, x509_keyUsage, x509_subjectAltName,
	signature_algo, parent_id, raw_cert ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11
	$12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24 )`,
		cert.Hashes.SHA1, cert.Hashes.SHA256, cert.Issuer.CommonName, cert.Subject.CommonName,
		cert.Version, cert.CA, cert.Validity.NotBefore, cert.Validity.NotAfter, cert.FirstSeenTimestamp,
		cert.LastSeenTimestamp, cert.X509v3BasicConstraints, cert.X509v3Extensions.CRLDistributionPoints,
		cert.X509v3Extensions.ExtendedKeyUsage, cert.X509v3Extensions.AuthorityKeyId,
		cert.X509v3Extensions.SubjectKeyId, cert.X509v3Extensions.KeyUsage,
		cert.X509v3Extensions.SubjectAlternativeName, cert.SignatureAlgorithm,
		cert.ParentSignature, cert.Raw)

	return err
}

func (db *DB) UpdateCertLastSeen(cert *certificate.Certificate) error {

	_, err := db.Exec("UPDATE certificates SET last_seen=$1 WHERE sha1_fingerprint=$2", cert.LastSeenTimestamp, cert.Hashes.SHA1)
	return err
}

func (db *DB) GetCertwithFingerprint(sha1 string) (*certificate.Certificate, error) {

	row := db.QueryRow(`SELECT sha256_fingerprint,
		issuer, subject, version, is_ca, valid_not_before, valid_not_after, 
		first_seen, last_Seen, x509_basicConstraints, x509_crlDistPoints, x509_extendedKeyUsage
		x509_authorityKeyIdentifier, x509_subjectKeyIdentifier, x509_keyUsage, x509_subjectAltName,
		signature_algo, parent_id, raw_cert
		FROM certificates
		WHERE sha1_fingerprint=$1`, sha1)

	cert := &certificate.Certificate{}

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

func (db *DB) GetCertwithID(id string) (*certificate.Certificate, error) {

	row := db.QueryRow(`SELECT sha1_fingerprint,sha256_fingerprint,
		issuer, subject, version, is_ca, valid_not_before, valid_not_after, 
		first_seen, last_Seen, x509_basicConstraints, x509_crlDistPoints, x509_extendedKeyUsage
		x509_authorityKeyIdentifier, x509_subjectKeyIdentifier, x509_keyUsage, x509_subjectAltName,
		signature_algo, parent_id, raw_cert
		FROM certificates
		WHERE id=$1`, id)

	cert := &certificate.Certificate{}

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
