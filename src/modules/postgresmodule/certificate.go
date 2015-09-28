package postgresmodule

//using latest https://hub.docker.com/_/postgres/ image for testing

import (
	"certificate"
)

func (db *DB) InsertCertificate(cert *certificate.Certificate) error {

	var ubuntu_valid, mozilla_valid, msft_valid, apple_valid bool

	//TODO: iter through truststores and check above booleans.

	_, err := db.Exec(`INSERT INTO certificates(  sha1_fingerprint, sha256_fingerprint,
	issuer, subject, version, is_ca, valid_not_before, valid_not_after,
	first_seen, last_seen, is_ubuntu_valid, is_mozilla_valid, is_microsoft_valid, 
	is_apple_valid, x509_basicConstraints, x509_crlDistPoints, x509_extendedKeyUsage
	x509_authorityKeyIdentifier, x509_subjectKeyIdentifier, x509_keyUsage, x509_subjectAltName,
	signature_algo, parent_id, raw_cert ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11
	$12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24 )`,
		cert.Hashes.SHA1, cert.Hashes.SHA256, cert.Issuer.CommonName, cert.Subject.CommonName,
		cert.Version, cert.CA, cert.Validity.NotBefore, cert.Validity.NotAfter, cert.FirstSeenTimestamp,
		cert.LastSeenTimestamp, ubuntu_valid, mozilla_valid, msft_valid, apple_valid,
		cert.X509v3BasicConstraints, cert.X509v3Extensions.CRLDistributionPoints,
		cert.X509v3Extensions.ExtendedKeyUsage, cert.X509v3Extensions.AuthorityKeyId,
		cert.X509v3Extensions.SubjectKeyId, cert.X509v3Extensions.KeyUsage,
		cert.X509v3Extensions.SubjectAlternativeName, cert.SignatureAlgorithm,
		cert.ParentSignature /*TODO put whole raw cert into certificate struct*/)

	return err
}

//certificate DB schema ( not finalised )
//CREATE TABLE certificates  (
//	id                         	serial primary key,
//	sha1_fingerprint           	bytea NOT NULL,
//  sha256_fingerprint          bytea NOT NULL,
//	serial_number              	varchar NULL,
//	issuer_id                  	int4 NULL,
//	version                    	int2 NULL,
//	subject                    	varchar NULL,
//	issuer                     	varchar NULL,
//	is_ca                      	int2 NULL,
//	is_self_signed             	bool NULL,
//	not_valid_before           	timestamp NULL,
//	not_valid_after            	timestamp NULL,
//  first_seen					timestamp NULL,
//  last_seen					timestamp NULL,
//	is_valid                   	bool NULL,
//	validation_error           	varchar NULL,
//	is_ubuntu_valid           	bool NULL,
//	is_mozilla_valid           	bool NULL,
//	is_windows_valid           	bool NULL,
//	is_apple_valid             	bool NULL,
//	x509_basicConstraints      	varchar NULL,
//	x509_crlDistributionPoints 	varchar NULL,
//	x509_extendedKeyUsage      	varchar NULL,
//	x509_authorityKeyIdentifier	varchar NULL,
//	x509_subjectKeyIdentifier  	varchar NULL,
//	x509_keyUsage              	varchar NULL,
//	x509_certificatePolicies   	varchar NULL,
//	x509_authorityInfoAccess   	varchar NULL,
//	x509_subjectAltName        	varchar NULL,
//	x509_issuerAltName         	varchar NULL,
//	signature_algo             	varchar NULL,
//  parent_id					numeric NULL,
//	in_openssl_root_store      	bool NULL,
//	in_mozilla_root_store      	bool NULL,
//	in_windows_root_store      	bool NULL,
//	in_apple_root_store        	bool NULL,
//	is_revoked                 	bool NULL,
//	revoked_at                 	timestamp NULL,
//	raw_cert					varchar NOT NULL
//);

func (db *DB) UpdateCertLastSeen(cert *certificate.Certificate) error {

	_, err := db.Exec("UPDATE certificates SET last_seen=$1 WHERE sha1_fingerprint=$2", cert.LastSeenTimestamp, cert.Hashes.SHA1)
	return err
}

func (db *DB) GetCertwithFingerprint(sha1 string) (*certificate.Certificate, error) {

	var ubuntu_valid, mozilla_valid, msft_valid, apple_valid bool

	row := db.QueryRow(`SELECT sha256_fingerprint,
		issuer, subject, version, is_ca, valid_not_before, valid_not_after,
		first_seen, last_seen, is_ubuntu_valid, is_mozilla_valid, is_microsoft_valid, 
		is_apple_valid, x509_basicConstraints, x509_crlDistPoints, x509_extendedKeyUsage
		x509_authorityKeyIdentifier, x509_subjectKeyIdentifier, x509_keyUsage, x509_subjectAltName,
		signature_algo, parent_id, raw_cert
		FROM certificates
		WHERE sha1_fingerprint=$1`, sha1)

	cert := &certificate.Certificate{}

	err := row.Scan(&cert.Hashes.SHA256, &cert.Issuer.CommonName, &cert.Subject.CommonName,
		&cert.Version, &cert.CA, &cert.Validity.NotBefore, &cert.Validity.NotAfter, &cert.FirstSeenTimestamp,
		&cert.LastSeenTimestamp, &ubuntu_valid, &mozilla_valid, &msft_valid, &apple_valid,
		&cert.X509v3BasicConstraints, &cert.X509v3Extensions.CRLDistributionPoints,
		&cert.X509v3Extensions.ExtendedKeyUsage, &cert.X509v3Extensions.AuthorityKeyId,
		&cert.X509v3Extensions.SubjectKeyId, &cert.X509v3Extensions.KeyUsage,
		&cert.X509v3Extensions.SubjectAlternativeName, &cert.SignatureAlgorithm,
		&cert.ParentSignature)

	//TODO: parse boolean and recreate truststore validity
	//may have to think of another way to store that.

	if err != nil {
		return nil, err
	} else {
		return cert, nil
	}

}
