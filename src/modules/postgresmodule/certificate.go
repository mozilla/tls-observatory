package postgresmodule

import (
	"certificate"
)

func (db *DB) InsertCertificate(cert *certificate.Certificate) error {

	q := buildInsertQueryFromCert(cert)
	res, err := db.Exec(q)

	return err
}

//certificate DB schema ( not finalised )
//CREATE TABLE certificates  (
//	id                         	serial NOT NULL,
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
//	x509_nsCertType            	varchar NULL,
//	x509_nsComment             	varchar NULL,
//	x509_policyConstraints     	varchar NULL,
//	x509_privateKeyUsagePeriod 	varchar NULL,
//	x509_SMIME-CAPS            	varchar NULL,
//	x509_issuerAltName         	varchar NULL,
//	signature_algo             	openssl_nidln NULL,
//  parent_id					numeric NULL,
//	depth                      	int4 NULL,
//	public_key_id              	int4 NULL,
//	public_key_type            	openssl_nidln NULL,
//	in_openssl_root_store      	bool NULL,
//	in_mozilla_root_store      	bool NULL,
//	in_windows_root_store      	bool NULL,
//	in_apple_root_store        	bool NULL,
//	is_revoked                 	bool NULL,
//	revoked_at                 	timestamp NULL,
//	reason_revoked             	crl_reason NULL,
//	PRIMARY KEY(id)
//);

func buildInsertQueryFromCert(cert *certificate.Certificate) string {
	q := `INSERT INTO certificates( id, sha1_fingerprint, sha256_fingerprint,
	 serial_no, issuer, subject, version, is_ca, valid_not_before, valid_not_after,
	 first_seen, last_seen, is_ubuntu_valid, is_mozilla_valid, is_microsoft_valid, 
	 is_apple_valid, x509_basicConstraints, x509_crlDistPoints, x509_extendedKeyUsage
	 x509_authorityKeyIdentifier, x509_subjectKeyIdentifier, x509_keyUsage, x509_subjectAltName,
	 signature_algo, parent_id    )  `
}

func (db *DB) UpdateCertLastSeen(cert *certificate.Certificate) error {

}
