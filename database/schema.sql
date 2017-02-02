CREATE TABLE certificates(
    id                          serial primary key,
    sha1_fingerprint            varchar NOT NULL,
    sha256_fingerprint          varchar NOT NULL,
    sha256_subject_spki         varchar NOT NULL,
    pkp_sha256                  varchar NOT NULL,
    serial_number               varchar NULL,
    version                     integer NULL,
    domains                     varchar NULL,
    subject                     jsonb NULL,
    issuer                      jsonb NULL,
    is_ca                       bool NULL,
    not_valid_before            timestamp NULL,
    not_valid_after             timestamp NULL,
    first_seen                  timestamp NULL,
    last_seen                   timestamp NULL,
    key_alg                     varchar NULL,
    key                         jsonb NULL,
    x509_basicConstraints       varchar NULL,
    x509_crlDistributionPoints  jsonb NULL,
    x509_extendedKeyUsage       jsonb NULL,
    x509_authorityKeyIdentifier varchar NULL,
    x509_subjectKeyIdentifier   varchar NULL,
    x509_keyUsage               jsonb NULL,
    x509_certificatePolicies    jsonb NULL,
    x509_authorityInfoAccess    varchar NULL,
    x509_subjectAltName         jsonb NULL,
    x509_issuerAltName          varchar NULL,
    is_name_constrained         bool NULL,
    permitted_names             jsonb NULL,
    signature_algo              varchar NULL,
    in_ubuntu_root_store        bool NULL,
    in_mozilla_root_store       bool NULL,
    in_microsoft_root_store     bool NULL,
    in_apple_root_store         bool NULL,
    in_android_root_store       bool NULL,
    is_revoked                  bool NULL,
    revoked_at                  timestamp NULL,
    raw_cert                    varchar NOT NULL,
    permitted_dns_domains       varchar[] NOT NULL DEFAULT '{}',
    permitted_ip_addresses      varchar[] NOT NULL DEFAULT '{}',
    excluded_dns_domains        varchar[] NOT NULL DEFAULT '{}',
    excluded_ip_addresses       varchar[] NOT NULL DEFAULT '{}',
    is_technically_constrained  bool NOT NULL DEFAULT false,
    cisco_umbrella_rank         integer NOT NULL DEFAULT 2147483647
);
CREATE INDEX certificates_sha256_fingerprint_idx ON certificates(sha256_fingerprint);
CREATE INDEX certificates_subject_idx ON certificates(subject);
CREATE INDEX certificates_cisco_umbrella_rank ON certificates(cisco_umbrella_rank);
ALTER TABLE certificates ADD CONSTRAINT certificates_unique_sha256_fingerprint UNIQUE (sha256_fingerprint);

CREATE TABLE trust (
    id                serial primary key,
    cert_id           integer references certificates(id) NOT NULL,
    issuer_id         integer references certificates(id) NOT NULL,
    timestamp         timestamp NOT NULL,
    trusted_ubuntu    bool NULL,
    trusted_mozilla   bool NULL,
    trusted_microsoft bool NULL,
    trusted_apple     bool NULL,
    trusted_android   bool NULL,
    is_current        bool NOT NULL
);
CREATE INDEX trust_cert_id_idx ON trust(cert_id);
CREATE INDEX trust_issuer_id_idx ON trust(issuer_id);
CREATE INDEX trust_is_current_idx ON trust(is_current);

CREATE TABLE scans(
    id               serial primary key,
    timestamp        timestamp NOT NULL,
    target           varchar NOT NULL,
    replay           integer NULL,
    has_tls          bool NOT NULL,
    cert_id          integer references certificates(id) NULL,
    trust_id         integer references trust(id) NULL,
    is_valid         bool NOT NULL,
    completion_perc  integer NOT NULL,
    validation_error varchar NOT NULL,
    conn_info        jsonb NOT NULL,
    ack              bool NOT NULL,
    attempts         integer NULL,
    analysis_params  jsonb NOT NULL
);
CREATE INDEX scans_completion_attempts_idx ON scans(completion_perc, attempts);
CREATE INDEX scans_ack_idx ON scans(ack);
CREATE INDEX scans_target_idx ON scans(target);
CREATE INDEX scans_timestamp_idx ON scans(timestamp);
CREATE INDEX scans_cert_id_idx ON scans(cert_id);

CREATE TABLE analysis(
    id          serial primary key,
    scan_id     integer references scans(id),
    worker_name varchar NOT NULL,
    success     bool NOT NULL,
    output      jsonb NULL
);
CREATE INDEX analysis_scan_id_idx ON analysis(scan_id);

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
ALTER ROLE tlsobsapi WITH NOSUPERUSER INHERIT NOCREATEROLE NOCREATEDB LOGIN PASSWORD 'mysecretpassphrase';
GRANT SELECT ON analysis, certificates, scans, trust TO tlsobsapi;
GRANT INSERT ON scans, certificates, trust TO tlsobsapi;
GRANT USAGE ON scans_id_seq, certificates_id_seq, trust_id_seq TO tlsobsapi;

CREATE ROLE tlsobsscanner;
ALTER ROLE tlsobsscanner WITH NOSUPERUSER INHERIT NOCREATEROLE NOCREATEDB LOGIN PASSWORD 'mysecretpassphrase';
GRANT SELECT ON analysis, certificates, scans, trust TO tlsobsscanner;
GRANT INSERT ON analysis, certificates, scans, trust TO tlsobsscanner;
GRANT UPDATE ON analysis, certificates, scans, trust TO tlsobsscanner;
GRANT USAGE ON analysis_id_seq, certificates_id_seq, scans_id_seq, trust_id_seq TO tlsobsscanner;

