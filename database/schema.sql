CREATE TABLE certificates  (
	id                         	serial primary key,
	sha1_fingerprint           	varchar NOT NULL,
	sha256_fingerprint          varchar NOT NULL,
	serial_number              	varchar NULL,
	version                    	integer NULL,
	subject                    	jsonb NULL,
	issuer                     	jsonb NULL,
	is_ca                      	bool NULL,
	not_valid_before           	timestamp NULL,
	not_valid_after            	timestamp NULL,
	first_seen					timestamp NULL,
	last_seen					timestamp NULL,
	x509_basicConstraints      	varchar NULL,
	x509_crlDistributionPoints 	jsonb NULL,
	x509_extendedKeyUsage      	jsonb NULL,
	x509_authorityKeyIdentifier	varchar NULL,
	x509_subjectKeyIdentifier  	varchar NULL,
	x509_keyUsage              	jsonb NULL,
	x509_certificatePolicies   	varchar NULL,
	x509_authorityInfoAccess   	varchar NULL,
	x509_subjectAltName        	jsonb NULL,
	x509_issuerAltName         	varchar NULL,
	signature_algo             	varchar NULL,
	in_ubuntu_root_store      	bool NULL,
	in_mozilla_root_store      	bool NULL,
	in_microsoft_root_store     bool NULL,
	in_apple_root_store        	bool NULL,
	in_android_root_store       bool NULL,
	is_revoked                 	bool NULL,
	revoked_at                 	timestamp NULL,
	domains 										varchar NULL,
	raw_cert										varchar NOT NULL
);

CREATE TABLE trust (
    id                          serial primary key,
    cert_id                     integer references certificates(id) NOT NULL,
    issuer_id                   integer references certificates(id) NOT NULL,
    timestamp                   timestamp NOT NULL,
	trusted_ubuntu           	bool NULL,
	trusted_mozilla           	bool NULL,
	trusted_microsoft           bool NULL,
	trusted_apple             	bool NULL,
    trusted_android             bool NULL,
    is_current                  bool NOT NULL
);

CREATE TABLE scans  (
	id                         	serial primary key,
	timestamp	           		timestamp NOT NULL,
	target						varchar NOT NULL,
	replay 				        integer NULL,
	has_tls						bool NOT NULL,
	cert_id		              	integer references certificates(id) NULL,
    trust_id                    integer references trust(id) NULL,
	is_valid                   	bool NOT NULL,
	completion_perc				integer NOT NULL,
	validation_error           	varchar NOT NULL,
	conn_info                	jsonb NOT NULL,
	ack 						bool NOT NULL,
	attempts			        integer NULL
);

CREATE TABLE analysis  (
	id                         	serial primary key,
	scan_id		              	integer references scans(id),
	worker_name	           		varchar NOT NULL,
	output						jsonb NULL
);

CREATE FUNCTION notify_trigger() RETURNS trigger AS $$
DECLARE
BEGIN
  PERFORM pg_notify('scan_listener', ''||NEW.id );
  RETURN new;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER watched_table_trigger AFTER INSERT ON scans
FOR EACH ROW EXECUTE PROCEDURE notify_trigger();

CREATE ROLE tlsobsapi;
GRANT SELECT ON analysis, certificates, scans, trust TO tlsobsapi;
GRANT INSERT ON scans TO tlsobsapi;
GRANT USAGE ON scans_id_seq TO tlsobsapi;

CREATE ROLE tlsobsscanner;
GRANT SELECT ON analysis, certificates, scans, trust TO tlsobsscanner;
GRANT INSERT ON analysis, certificates, scans, trust TO tlsobsscanner;
GRANT UPDATE ON analysis, certificates, scans, trust TO tlsobsscanner;
GRANT USAGE ON analysis_id_seq, certificates_id_seq, scans_id_seq, trust_id_seq TO tlsobsscanner;
