# Mozilla TLS Observatory

## Want to scan your sites?

```bash
$ go get -u github.com/mozilla/tls-observatory/tlsobs
$ $GOPATH/bin/tlsobs mysite.example.net
```

## Clone this repository

```bash
$ git clone git@github.com:mozilla/tls-observatory.git
$ cd tls-observatory
$ git submodule update --init --recursive
$ git submodule update
```

## Build

Requires Go 1.5 with vendoring experiment enabled.

```bash
$ GO15VENDOREXPERIMENT=1 go get github.com/mozilla/tls-observatory/tlsobs-scanner
$ GO15VENDOREXPERIMENT=1 go get github.com/mozilla/tls-observatory/tlsobs-api
```

## Deployment

Create the Postgres database using the SQL instructions in
`database/schema.sql`, the create two configuration files for the api and the
scanner using the templates in `conf/`.

For AWS deployment, you can use the ElasticBeanstalk environment creation script
in `tools/aws-create-env.sh`. The script creates an RDS database and an EB
application with two environment, one for the api, one for the scanner.

```bash
$ assume-aws-role moz-dev <mfa-token>
aws$ bash aws-create-env.sh
```
Once the environment created, log into the web console and create two
applications versions: one for the api, and one for the scanner. Use the JSON
templates provided in `tools/tls-observatory-api-elasticbeanstalk.json` and
`tools/tls-observatory-scanner-elasticbeanstalk.json`. 

## Configuration

### tlsobs-runner
Runs regular tests against target sites and sends notifications.

See `conf/runnel.yaml` for an example of configuration. The configuration can
also be provided by environment variables:

* TLSOBS_RUNNER_SMTP_HOST, TLSOBS_RUNNER_SMTP_PORT, TLSOBS_RUNNER_SMTP_FROM,
  TLSOBS_RUNNER_SMTP_AUTH_USER and TLSOBS_RUNNER_SMTP_AUTH_PASS can be set to
  define specific SMTP settings that override both local conf and
  TLSOBS_RUNNER_CONF.

##Authors##

 * Dimitris Bachtis
 * Julien Vehent

##License##

 * Mozilla Public License Version 2.0

## Queries

### Find certificates signed by CAs identified by their SHA256 fingerprint

```sql
SELECT certificates.id, certificates.subject, certificates.issuer
FROM certificates INNER JOIN trust ON (certificates.id=trust.cert_id)
WHERE trust.issuer_id in (
    SELECT id FROM certificates
    WHERE sha256_fingerprint IN (
        'E7685634EFACF69ACE939A6B255B7B4FABEF42935B50A265ACB5CB6027E44E70',
        'A4B6B3996FC2F306B3FD8681BD63413D8C5009CC4FA329C2CCF0E2FA1B140305'
    ))
AND certificates.is_ca='false';
```

### List signature algorithms of trusted certs

```sql
SELECT signature_algo, count(*)
FROM certificates INNER JOIN trust ON (certificates.id=trust.cert_id)
WHERE is_ca='false'
AND trust.trusted_mozilla='true'
GROUP BY signature_algo
ORDER BY count(*) DESC;
```

### Show expiration dates of trusted SHA-1 certificates

```sql
SELECT  extract('year' FROM date_trunc('year', not_valid_after)) as expiration_year,
        extract('month' FROM date_trunc('month', not_valid_after)) as expiration_month,
        count(*)
FROM    certificates
    INNER JOIN trust ON (certificates.id=trust.cert_id)
WHERE is_ca='false'
    AND trust.trusted_mozilla='true'
    AND signature_algo='SHA1WithRSA'
GROUP BY date_trunc('year', not_valid_after),
         date_trunc('month', not_valid_after)
ORDER BY date_trunc('year', not_valid_after) ASC,
         date_trunc('month', not_valid_after) ASC;
```

### List issuer, subject and SAN of Mozilla|Firefox certs not issued by Digicert

```sql
SELECT  id,
        issuer->'o'->>0 AS Issuer,
        subject->>'cn' AS Subject,
        san AS SubjectAltName
FROM  certificates,
      jsonb_array_elements_text(x509_subjectAltName) as san
WHERE jsonb_typeof(x509_subjectAltName) != 'null'
      AND ( subject#>>'{cn}' ~ '\.(firefox|mozilla)\.'
            OR san ~ '\.(firefox|mozilla)\.')
      AND cast(issuer#>>'{o}' AS text) NOT LIKE '%DigiCert Inc%'
ORDER BY id ASC;
```

### Find count of targets that support the SEED-SHA ciphersuite

```sql
SELECT COUNT(DISTINCT(target))
FROM scans, jsonb_array_elements(conn_info->'ciphersuite') as ciphersuites
WHERE jsonb_typeof(conn_info) != 'null'
AND ciphersuites->>'cipher'='SEED-SHA';
```
