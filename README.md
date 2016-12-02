# Mozilla TLS Observatory

Want the WebUI? Check out [Mozilla's Observatory](https://observatory.mozilla.org) !

* [Mozilla TLS Observatory](#mozilla-tls-observatory)
  * [Getting started](#getting-started)
    * [Using the tlsobs client from Docker](#using-the-tlsobs-client-from-docker)
  * [Developing](#developing)
    * [Create the database](#create-the-database)
    * [Starting the API and Scanner](#starting-the-api-and-scanner)
    * [Run a scan locally](#run-a-scan-locally)
    * [Configuration](#configuration)
      * [tlsobs-api](#tlsobs-api)
      * [tlsobs-scanner](#tlsobs-scanner)
      * [tlsobs-runner](#tlsobs-runner)
  * [API Endpoints](#api-endpoints)
    * [POST /api/v1/scan](#post-/api/v1/scan)
    * [GET /api/v1/results](#get-/api/v1/results)
    * [GET /api/v1/certificate](#get-/api/v1/certificate)
    * [POST /api/v1/certificate](#post-/api/v1/certificate)
    * [GET /api/v1/paths](#get-/api/v1/paths)
    * [GET /api/v1/truststore](#get-/api/v1/truststore)
  * [Database Queries](#database-queries)
    * [Find certificates signed by CAs identified by their SHA256 fingerprint](#find-certificates-signed-by-cas-identified-by-their-sha256-fingerprint)
    * [List signature algorithms of trusted certs](#list-signature-algorithms-of-trusted-certs)
    * [Show expiration dates of trusted SHA-1 certificates](#show-expiration-dates-of-trusted-sha-1-certificates)
    * [List issuer, subject and SAN of Mozilla|Firefox certs not issued by Digicert](#list-issuer,-subject-and-san-of-mozilla|firefox-certs-not-issued-by-digicert)
    * [Find count of targets that support the SEED-SHA ciphersuite](#find-count-of-targets-that-support-the-seed-sha-ciphersuite)
    * [Find intermediate CA certs whose root is trusted by Mozilla](#find-intermediate-ca-certs-whose-root-is-trusted-by-mozilla)
    * [Find CA certs treated as EV in Firefox](#find-ca-certs-treated-as-ev-in-firefox)
  * [Core contributors](#core-contributors)
  * [License](#license)

## Getting started

You can use the TLS Observatory to compare your site against the mozilla guidelines.
It requires Golang 1.7+ to be installed:
```bash
$ go version
go version go1.7 linux/amd64
 
$ export GOPATH="$HOME/go"
$ mkdir $GOPATH
 
$ export PATH=$GOPATH/bin:$PATH
```
Then get the binary:
```bash
$ go get github.com/mozilla/tls-observatory/tlsobs
```
And scan using our hosted service:
```bash
$ tlsobs tls-observatory.services.mozilla.com
Scanning tls-observatory.services.mozilla.com (id 13528951)
Retrieving cached results from 20h33m1.379461888s ago. To run a new scan, use '-r'.

--- Certificate ---
Subject  C=US, O=Mozilla Corporation, CN=tls-observatory.services.mozilla.com
SubjectAlternativeName
- tls-observatory.services.mozilla.com
Validity 2016-01-20T00:00:00Z to 2017-01-24T12:00:00Z
SHA1     FECA3CA0F4B726D062A76F47635DD94A37985105
SHA256   315A8212CBDC76FF87AEB2161EDAA86E322F7C18B27152B5CB9206297F3D3A5D
SigAlg   ECDSAWithSHA256
Key      ECDSA 384bits P-384
ID       1281826

--- Trust ---
Mozilla Microsoft Apple Android
   ✓        ✓       ✓      ✓

--- Chain of trust ---
C=US, O=Mozilla Corporation, CN=tls-observatory.services.mozilla.com (id=1281826)
└──C=US, O=DigiCert Inc, CN=DigiCert ECC Secure Server CA (id=5922)
   └──C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert Global Root CA (id=41)



--- Ciphers Evaluation ---
prio cipher                        protocols pfs                curves
1    ECDHE-ECDSA-AES128-GCM-SHA256 TLSv1.2   ECDH,P-256,256bits prime256v1
2    ECDHE-ECDSA-AES256-GCM-SHA384 TLSv1.2   ECDH,P-256,256bits prime256v1
OCSP Stapling        false
Server Side Ordering true
Curves Fallback      false

--- Analyzers ---
* Mozilla evaluation: modern
  - for modern level: consider adding ciphers ECDHE-RSA-AES256-GCM-SHA384, ECDHE-ECDSA-CHACHA20-POLY1305, ECDHE-RSA-CHACHA20-POLY1305, ECDHE-RSA-AES128-GCM-SHA256, ECDHE-ECDSA-AES256-SHA384, ECDHE-RSA-AES256-SHA384, ECDHE-ECDSA-AES128-SHA256, ECDHE-RSA-AES128-SHA256
  - for modern level: consider enabling OCSP stapling
  - for modern level: increase priority of ECDHE-ECDSA-AES256-GCM-SHA384 over ECDHE-ECDSA-AES128-GCM-SHA256
  - for modern level: fix ciphersuite ordering, use recommended modern ciphersuite
  - oldest clients: Firefox 27, Chrome 30, IE 11 on Windows 7, Edge 1, Opera 17, Safari 9, Android 5.0, Java 8
* Grade: A (93/100)
```

The analysis at the end tell you what need to be changed to reach the old, intermediate or modern level. We recommend to target the intermediate level by default, and modern if you don't care about old clients.

### Using the tlsobs client from Docker

A docker container also exists that contains the CLI, API, Scanner and Runner.
Fetch is from `docker pull mozilla/tls-observatory`.
```bash
$ docker pull mozilla/tls-observatory
$ docker run -it mozilla/tls-observatory tlsobs accounts.firefox.com
```

## Developing

You can use the `mozilla/tls-observatory` docker container for development:
```bash
$ docker pull mozilla/tls-observatory
$ docker run -it mozilla/tls-observatory /bin/bash
root@05676e6789dd:~# cd $GOPATH/src/github.com/mozilla/tls-observatory
root@05676e6789dd:/go/src/github.com/mozilla/tls-observatory# make
```
However, even with the docker container, you will need to setup your own
postgresql database. See below.

To build a development environment from scratch, you will need Go 1.7 or above.
You can set it up on your own machine or via the `golang:1.7` Docker
container.

Retrieve a copy of the source code using `go get`, to place it directly
under `$GOPATH/src/github.com/mozilla/tls-observatory`, then use `make`
to build all components.

```bash
$ docker run -it golang:1.7

root@c63f11b8852b:/go# go get github.com/mozilla/tls-observatory 
package github.com/mozilla/tls-observatory: no buildable Go source files in /go/src/github.com/mozilla/tls-observatory

root@c63f11b8852b:/go# cd $GOPATH/src/github.com/mozilla/tls-observatory

root@c63f11b8852b:/go/src/github.com/mozilla/tls-observatory# make
```

`make` runs the tests and compiles the scanner, api, command line client
and runner. The resulting binaries are placed under `$GOPATH/bin`.

### Create the database

TLS Observatory uses PostgreSQL > 9.4. To create a database, use the
schema in `database/schema.sql`.

```bash
postgres=# create database observatory;
CREATE DATABASE

postgres=# \c observatory
You are now connected to database "observatory" as user "postgres".

postgres=# \i /go/src/github.com/mozilla/tls-observatory/database/schema.sql 
```
This automatically creates all tables, indexes, users and grants to work
with the default configuration.

### Starting the API and Scanner

First symlink the configuration to /etc/observatory and the cipherscan
executable to /opt/cipherscan, as follows:
```bash
root@c63f11b8852b:/# ln -s $GOPATH/src/github.com/mozilla/tls-observatory/conf /etc/tls-observatory
root@c63f11b8852b:/# ln -s $GOPATH/src/github.com/mozilla/tls-observatory/cipherscan /opt/cipherscan
```
Then start `tlsobs-api` and `tlsobs-scanner`. The API will listen on port 8083,
on localhost (or 172.17.0.2 if you're running in Docker).

### Run a scan locally

To run a scan using the local scanner, set the `-observatory` flag of the `tlsobs`
client to use the local API, as follows:
```bash
$ tlsobs -observatory http://172.17.0.2:8083 ulfr.io
```

### Configuration

#### tlsobs-api

Customize the configuration file under `conf/api.cfg` and using the following
environment variables:
* `TLSOBS_API_ENABLE` set to `on` or `off` to enable or disable the API
* `TLSOBS_POSTGRES` is the hostname or IP of the database server (eg. `mypostgresdb.example.net`)
* `TLSOBS_POSTGRESDB` is the name of the database (eg. `observatory`)
* `TLSOBS_POSTGRESUSER` is the database user (eg. `tlsobsapi`)
* `TLSOBS_POSTGRESPASS` is the database user password (eg. `mysecretpassphrase`)

#### tlsobs-scanner

Customize the configuration file under `conf/scanner.cfg` and using the
following environment variables:
* `TLSOBS_SCANNER_ENABLE` set to `on` or `off` to enable or disable the scabber
* `TLSOBS_POSTGRES` is the hostname or IP of the database server (eg. `mypostgresdb.example.net`)
* `TLSOBS_POSTGRESDB` is the name of the database (eg. `observatory`)
* `TLSOBS_POSTGRESUSER` is the database user (eg. `tlsobsscanner`)
* `TLSOBS_POSTGRESPASS` is the database user password (eg. `mysecretpassphrase`)

#### tlsobs-runner

Runs regular tests against target sites and sends notifications.

See `conf/runnel.yaml` for an example of configuration. Some configuration
parameters can also be provided through environment variables:

* `TLSOBS_RUNNER_SMTP_HOST` is the hostname of the smtp server (eg. `mypostfix.example.net`)
* `TLSOBS_RUNNER_SMTP_PORT` is the port of the smtp server (eg. `587`)
* `TLSOBS_RUNNER_SMTP_FROM` is the from address of email notifications sent by the runner (eg. `mynotification@tlsobservatory.example.net`)
* `TLSOBS_RUNNER_SMTP_AUTH_USER` is the smtp authenticated username (eg `tlsobsrunner`)
* `TLSOBS_RUNNER_SMTP_AUTH_PASS` is the smtp user password (eg. `mysecretpassphrase`)

## API Endpoints

### POST /api/v1/scan

Schedule a scan of a given target.

```bash
$ curl -X POST 'https://tls-observatory.services.mozilla.com/api/v1/scan?target=ulfr.io&rescan=true'
```

**Parameters**:

* `target` is the FQDN of the target site. eg. `google.com`. Do not use protocol handlers or query strings.
* `rescan` asks for a rescan of the target when set to true.
* `params` JSON object in which each key represents one of TLS Observatory's workers. The value under each key will be passed as the parameters to the corresponding worker. For example, `{"ev-checker": {"oid": "foo"}}` will pass `{"oid": "foo"}` to the ev-checker worker. The following workers accept parameters:
  * ev-checker: Expects a JSON object with the following keys:
    * oid: the oid of the EV policy to check
    * rootCertificate: the root certificate to check against, in PEM format

For example, with curl:

```
curl -X POST "http://localhost:8083/api/v1/scan?target=mozilla.org&rescan=true&params=%7B%0A%20%20%22ev-checker%22%3A%20%7B%0A%20%20%22rootcertificate%22%3A%20%22-----BEGIN%20CERTIFICATE-----%5CnMIIDxTCCAq2gAwIBAgIQAqxcJmoLQJuPC3nyrkYldzANBgkqhkiG9w0BAQUFADBs%5CnMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3%5Cnd3cuZGlnaWNlcnQuY29tMSswKQYDVQQDEyJEaWdpQ2VydCBIaWdoIEFzc3VyYW5j%5CnZSBFViBSb290IENBMB4XDTA2MTExMDAwMDAwMFoXDTMxMTExMDAwMDAwMFowbDEL%5CnMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3%5CnLmRpZ2ljZXJ0LmNvbTErMCkGA1UEAxMiRGlnaUNlcnQgSGlnaCBBc3N1cmFuY2Ug%5CnRVYgUm9vdCBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMbM5XPm%5Cn%2B9S75S0tMqbf5YE%2Fyc0lSbZxKsPVlDRnogocsF9ppkCxxLeyj9CYpKlBWTrT3JTW%5CnPNt0OKRKzE0lgvdKpVMSOO7zSW1xkX5jtqumX8OkhPhPYlG%2B%2BMXs2ziS4wblCJEM%5CnxChBVfvLWokVfnHoNb9Ncgk9vjo4UFt3MRuNs8ckRZqnrG0AFFoEt7oT61EKmEFB%5CnIk5lYYeBQVCmeVyJ3hlKV9Uu5l0cUyx%2BmM0aBhakaHPQNAQTXKFx01p8VdteZOE3%5CnhzBWBOURtCmAEvF5OYiiAhF8J2a3iLd48soKqDirCmTCv2ZdlYTBoSUeh10aUAsg%5CnEsxBu24LUTi4S8sCAwEAAaNjMGEwDgYDVR0PAQH%2FBAQDAgGGMA8GA1UdEwEB%2FwQF%5CnMAMBAf8wHQYDVR0OBBYEFLE%2Bw2kD%2BL9HAdSYJhoIAu9jZCvDMB8GA1UdIwQYMBaA%5CnFLE%2Bw2kD%2BL9HAdSYJhoIAu9jZCvDMA0GCSqGSIb3DQEBBQUAA4IBAQAcGgaX3Nec%5CnnzyIZgYIVyHbIUf4KmeqvxgydkAQV8GK83rZEWWONfqe%2FEW1ntlMMUu4kehDLI6z%5CneM7b41N5cdblIZQB2lWHmiRk9opmzN6cN82oNLFpmyPInngiK3BD41VHMWEZ71jF%5CnhS9OMPagMRYjyOfiZRYzy78aG6A9%2BMpeizGLYAiJLQwGXFK3xPkKmNEVX58Svnw2%5CnYzi9RKR%2F5CYrCsSXaQ3pjOLAEFe4yHYSkVXySGnYvCoCWw9E1CAx2%2FS6cCZdkGCe%5CnvEsXCS%2B0yx5DaMkHJ8HSXPfqIbloEpw8nL%2Be%2FIBcm2PN7EeqJSdnoDfzAIJ9VNep%5Cn%2BOkuE6N36B9K%5Cn-----END%20CERTIFICATE-----%22%2C%0A%20%20%22oid%22%3A%20%222.16.840.1.114412.22.1%22%0A%7D%0A%7D"
```

**Output**: a `json` document containing the Scan ID.

**Caching**: When `rescan` is not `true`, if a scan of the target was done over the last 24 hours, the scan ID is returned. Use `rescan=true` to force a rescan within 24 hours of the previous scan.

**Rate Limits**: Each target can only be scanned every 3 minutes with `rescan=true`.

### GET /api/v1/results

Retrieve scan results by its ID.

```bash
curl https://tls-observatory.services.mozilla.com/api/v1/results?id=12302333
```

**Parameters**:

* `id` is the Scan ID

**Output**: a `json` document containing the scan results and the ID of the end-entity certificate.

### GET /api/v1/certificate

Retrieve a certificate by its ID.

```bash
curl https://tls-observatory.services.mozilla.com/api/v1/certificate?id=1
```

**Parameters**:

* `id` is the Certificate ID
* `sha256` the hexadecimal checksum of the DER certificate (only if `id` is not
  provided)

**Output**: a `json` document containing the parsed certificate and its raw X509 version encoded with base64.

### POST /api/v1/certificate

Publish a certificate.

```bash
curl -X POST -F certificate=@example.pem https://tls-observatory.services.mozilla.com/api/v1/certificate
```

**Parameters**:

* `certificate` is a POST multipart/form-data parameter that contains the PEM encoded certificate.

**Output**: a `json` document containing the parsed certificate and its raw X509 version encoded with base64.

**Caching**: Certificates are only stored once. The database uses the SHA256 hash of the DER (binary) certificate to identify duplicates. Posting a certificate already stored in database returns the stored version. 

### GET /api/v1/paths

Retrieve the paths from a certificate to one of multiple roots.

```bash
curl https://tls-observatory.services.mozilla.com/api/v1/paths?id=1
```

**Parameters**:

* `id` is the ID of the certificate to start the path at.
* `sha256` the hexadecimal checksum of the DER certificate (only if `id` is not
  provided)

**Output**: a `json` document containing the paths document. Each entry in the path contains the current certificate and an array of parents, if any exist.

### GET /api/v1/truststore

Retrieve all the certificates in a given truststore.

```bash
curl https://tls-observatory.services.mozilla.com/api/v1/truststore?store=mozilla&format=pem
```

**Parameters**:

* `store` is the store to retrieve certificates from. "mozilla", "android", "apple", "microsoft" and "ubuntu" are allowed.
* `format`, either "pem" or "json". 

**Output**: if `format` is pem, a series of PEM-format certificates. If `format` is json, a json array of certificate objects, each with the same format of `/api/v1/certificate`.

## Database Queries

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
SELECT certificates.id,
       issuer->'o'->>0 AS Issuer,
       subject->>'cn' AS Subject,
       san AS SubjectAltName
FROM certificates
      INNER JOIN trust ON (trust.cert_id=certificates.id),
     jsonb_array_elements_text(x509_subjectAltName) AS san
WHERE jsonb_typeof(x509_subjectAltName) != 'null'
      AND ( subject#>>'{cn}' ~ '\.(firefox|mozilla)\.'
            OR
            san ~ '\.(firefox|mozilla)\.'
          )
      AND trust.trusted_mozilla='true'
      AND certificates.not_valid_after>now()
      AND cast(issuer#>>'{o}' AS text) NOT LIKE '%DigiCert Inc%'
GROUP BY certificates.id, san
ORDER BY certificates.id ASC;
```

### Find count of targets that support the SEED-SHA ciphersuite

```sql
SELECT COUNT(DISTINCT(target))
FROM scans, jsonb_array_elements(conn_info->'ciphersuite') as ciphersuites
WHERE jsonb_typeof(conn_info) != 'null'
AND ciphersuites->>'cipher'='SEED-SHA';
```

### Find intermediate CA certs whose root is trusted by Mozilla

```sql
SELECT id, subject
FROM certificates
WHERE is_ca=True
  AND subject!=issuer
  AND issuer IN (
      SELECT subject
      FROM certificates
      WHERE in_mozilla_root_store=True
  )
GROUP BY subject, sha256_fingerprint;
```

### Find CA certs treated as EV in Firefox

The list is CA Certs that get EV treatment in Firefox can be [found here](https://dxr.mozilla.org/mozilla-central/source/security/certverifier/ExtendedValidation.cpp).

```sql
SELECT id, subject
FROM certificates,
     jsonb_array_elements_text(x509_certificatePolicies) AS cpol
WHERE jsonb_typeof(x509_certificatePolicies) != 'null'
  AND cpol IN ('1.2.392.200091.100.721.1','1.2.616.1.113527.2.5.1.1','1.3.159.1.17.1',
               '1.3.6.1.4.1.13177.10.1.3.10','1.3.6.1.4.1.13769.666.666.666.1.500.9.1',
               '1.3.6.1.4.1.14370.1.6','1.3.6.1.4.1.14777.6.1.1','1.3.6.1.4.1.14777.6.1.2',
               '1.3.6.1.4.1.17326.10.14.2.1.2','1.3.6.1.4.1.17326.10.8.12.1.2',
               '1.3.6.1.4.1.22234.2.14.3.11','1.3.6.1.4.1.22234.2.5.2.3.1',
               '1.3.6.1.4.1.22234.3.5.3.1','1.3.6.1.4.1.22234.3.5.3.2','1.3.6.1.4.1.23223.1.1.1',
               '1.3.6.1.4.1.29836.1.10','1.3.6.1.4.1.34697.2.1','1.3.6.1.4.1.34697.2.2',
               '1.3.6.1.4.1.34697.2.3','1.3.6.1.4.1.34697.2.4','1.3.6.1.4.1.36305.2',
               '1.3.6.1.4.1.40869.1.1.22.3','1.3.6.1.4.1.4146.1.1','1.3.6.1.4.1.4788.2.202.1',
               '1.3.6.1.4.1.6334.1.100.1','1.3.6.1.4.1.6449.1.2.1.5.1','1.3.6.1.4.1.782.1.2.1.8.1',
               '1.3.6.1.4.1.7879.13.24.1','1.3.6.1.4.1.8024.0.2.100.1.2','2.16.156.112554.3',
               '2.16.528.1.1003.1.2.7','2.16.578.1.26.1.3.3','2.16.756.1.83.21.0',
               '2.16.756.1.89.1.2.1.1','2.16.756.5.14.7.4.8','2.16.792.3.0.3.1.1.5',
               '2.16.792.3.0.4.1.1.4','2.16.840.1.113733.1.7.23.6','2.16.840.1.113733.1.7.48.1',
               '2.16.840.1.114028.10.1.2','2.16.840.1.114404.1.1.2.4.1','2.16.840.1.114412.2.1',
               '2.16.840.1.114413.1.7.23.3','2.16.840.1.114414.1.7.23.3')
  AND is_ca='true';
```
## Core contributors

 * Julien Vehent (lead maintainer)
 * Dimitris Bachtis (original dev)
 * Adrian Utrilla

## License

 * Mozilla Public License Version 2.0
