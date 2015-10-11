CREATE TABLE scans  (
	id                         	serial primary key,
	time_stamp	           		timestamp NOT NULL,
	target						varchar NOT NULL,
	replay 				        integer NULL, //hours or days
	has_tls						bool NOT NULL,
	cert_id		              	varchar references certificates(id),
	is_valid                   	bool NULL,
	validation_error           	varchar NULL,
	is_ubuntu_valid           	bool NULL,
	is_mozilla_valid           	bool NULL,
	is_windows_valid           	bool NULL,
	is_apple_valid             	bool NULL,
	conn_info                	jsonb NULL
);

CREATE TABLE worker_output  (
	id                         	serial primary key,
	scan_id		              	varchar references scans(id),
	worker_name	           		varchar NOT NULL,
	output						jsonb NULL
);

CREATE TABLE certificates  (
	id                         	serial primary key,
	sha1_fingerprint           	bytea NOT NULL,
	sha256_fingerprint          bytea NOT NULL,
	serial_number              	varchar NULL,
	version                    	integer NULL,
	subject                    	varchar NULL,
	issuer                     	varchar NULL,
	is_ca                      	bool NULL,
	not_valid_before           	timestamp NULL,
	not_valid_after            	timestamp NULL,
	first_seen					timestamp NULL,
	last_seen					timestamp NULL,
	x509_basicConstraints      	varchar NULL,
	x509_crlDistributionPoints 	varchar NULL,
	x509_extendedKeyUsage      	varchar NULL,
	x509_authorityKeyIdentifier	varchar NULL,
	x509_subjectKeyIdentifier  	varchar NULL,
	x509_keyUsage              	varchar NULL,
	x509_certificatePolicies   	varchar NULL,
	x509_authorityInfoAccess   	varchar NULL,
	x509_subjectAltName        	varchar NULL,
	x509_issuerAltName         	varchar NULL,
	signature_algo             	varchar NULL,
	parent_id					numeric NULL,
	in_openssl_root_store      	bool NULL,
	in_mozilla_root_store      	bool NULL,
	in_windows_root_store      	bool NULL,
	in_apple_root_store        	bool NULL,
	is_revoked                 	bool NULL,
	revoked_at                 	timestamp NULL,
	raw_cert					varchar NOT NULL
);