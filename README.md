# Mozilla TLS Observatory

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
