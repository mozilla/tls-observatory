# Mozilla TLS Observatory

Want the WebUI? Check out [Mozilla's Observatory](https://observatory.mozilla.org) !

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
$ tlsobs twitter.com
Scanning twitter.com (id 12302241)
Retrieving cached results from 35m44.249807364s ago. To run a new scan, use '-r'.

--- Certificate ---
Subject  C=US, O=Twitter, Inc., OU=Twitter Security, CN=twitter.com
SubjectAlternativeName
- twitter.com
- www.twitter.com
Validity 2016-03-09T00:00:00Z to 2018-03-14T12:00:00Z
CA       false
SHA1     235A79B3270D790505E0BEA2CF5C149F9038821B
SHA256   334105950462AEAB4EAE05B74DF693FA6D73250ED152204778A2B7BD9CF5FD6A
SigAlg   SHA256WithRSA
Key      RSA 2048bits 

--- Trust ---
Mozilla Microsoft Apple Android
   ✓        ✓       ✓      ✓

--- Chain of trust ---
0:	C=US, O=Twitter, Inc., OU=Twitter Security, CN=twitter.com
	issuer: C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert SHA2 Extended Validation Server CA
	type: end entity
	key: RSA 2048bits 
	pin-sha256: PS12nvydU5dSxolqCn3V11wWF5Z12JRhXT2dhyawT4M=

1:	C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert SHA2 Extended Validation Server CA
	issuer: C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert High Assurance EV Root CA
	type: intermediate CA
	key: RSA 2048bits 
	pin-sha256: RRM1dGqnDFsCJXBTHky16vi1obOlCgFFn/yOhI/y+ho=

2:	C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert High Assurance EV Root CA
	issuer: C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert High Assurance EV Root CA
	type: root CA
	key: RSA 2048bits 
	pin-sha256: WoiWRyIOVNa9ihaBciRSC7XHjliYS9VwUGOIud4PB18=



--- Ciphers Evaluation ---
prio cipher                      protocols             pfs                curves
1    ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2               ECDH,P-256,256bits prime256v1
2    ECDHE-RSA-AES128-SHA256     TLSv1.2               ECDH,P-256,256bits prime256v1
3    ECDHE-RSA-AES128-SHA        TLSv1,TLSv1.1,TLSv1.2 ECDH,P-256,256bits prime256v1
4    ECDHE-RSA-AES256-GCM-SHA384 TLSv1.2               ECDH,P-256,256bits prime256v1
5    ECDHE-RSA-AES256-SHA384     TLSv1.2               ECDH,P-256,256bits prime256v1
6    ECDHE-RSA-AES256-SHA        TLSv1,TLSv1.1,TLSv1.2 ECDH,P-256,256bits prime256v1
7    AES128-GCM-SHA256           TLSv1.2               None               
8    AES128-SHA256               TLSv1.2               None               
9    AES128-SHA                  TLSv1,TLSv1.1,TLSv1.2 None               
10   AES256-GCM-SHA384           TLSv1.2               None               
11   AES256-SHA256               TLSv1.2               None               
12   AES256-SHA                  TLSv1,TLSv1.1,TLSv1.2 None               
13   ECDHE-RSA-DES-CBC3-SHA      TLSv1,TLSv1.1,TLSv1.2 ECDH,P-256,256bits prime256v1
14   DES-CBC3-SHA                TLSv1,TLSv1.1,TLSv1.2 None               
OCSP Stapling        false
Server Side Ordering true
Curves Fallback      false

--- Analyzers ---
Measured level "intermediate" does not match target level "modern"
* Mozilla evaluation: intermediate
  - for modern level: remove ciphersuites ECDHE-RSA-AES128-SHA, ECDHE-RSA-AES256-SHA, AES128-GCM-SHA256, AES128-SHA256, AES128-SHA, AES256-GCM-SHA384, AES256-SHA256, AES256-SHA, ECDHE-RSA-DES-CBC3-SHA, DES-CBC3-SHA
  - for modern level: consider adding ciphers ECDHE-ECDSA-AES256-GCM-SHA384, ECDHE-ECDSA-CHACHA20-POLY1305, ECDHE-RSA-CHACHA20-POLY1305, ECDHE-ECDSA-AES128-GCM-SHA256, ECDHE-ECDSA-AES256-SHA384, ECDHE-ECDSA-AES128-SHA256
  - for modern level: remove protocols TLSv1, TLSv1.1
  - for modern level: consider enabling OCSP stapling
  - for modern level: use a certificate of type ecdsa, not RSA
  - oldest clients: Firefox 1, Chrome 1, IE 7, Opera 5, Safari 1, Windows XP IE8, Android 2.3, Java 7
* Grade: A (92/100)

```

The analysis at the end tell you what need to be changed to reach the old, intermediate or modern level. We recommend to target the intermediate level by default, and modern if you don't care about old clients.

### Using Docker

A docker container also exists that contains the CLI, API, Scanner and Runner.
Fetch is from `docker pull mozilla/tls-observatory`.
```bash
$ docker pull mozilla/tls-observatory
$ docker run -it mozilla/tls-observatory tlsobs accounts.firefox.com
```

## Contributing
### Clone this repository

```bash
$ git clone git@github.com:mozilla/tls-observatory.git
$ cd tls-observatory
$ git submodule update --init --recursive
$ git submodule update
```

### Build

Requires Go 1.7.

```bash
go install github.com/mozilla/tls-observatory/tlsobs-scanner
go install github.com/mozilla/tls-observatory/tlsobs-api
go install github.com/mozilla/tls-observatory/tlsobs-runner
go install github.com/mozilla/tls-observatory/tlsobs
```

### Deployment

Create the Postgres database using the schema in `database/schema.sql`.

Then create two configuration files for the api and the scanner using the templates in `conf/`.

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

### Configuration

#### tlsobs-api

Customize the configuration file under `conf/api.cfg`.

#### tlsobs-scanner

Customize the configuration file under `conf/scanner.cfg`.

#### tlsobs-runner

Runs regular tests against target sites and sends notifications.

See `conf/runnel.yaml` for an example of configuration. The configuration can
also be provided by environment variables:

* TLSOBS_RUNNER_SMTP_HOST, TLSOBS_RUNNER_SMTP_PORT, TLSOBS_RUNNER_SMTP_FROM,
  TLSOBS_RUNNER_SMTP_AUTH_USER and TLSOBS_RUNNER_SMTP_AUTH_PASS can be set to
  define specific SMTP settings that override both local conf and
  TLSOBS_RUNNER_CONF.

## Development

### API Endpoints

#### POST /api/v1/scan

Schedule a scan of a given target.

```bash
$ curl -X POST 'https://tls-observatory.services.mozilla.com/api/v1/scan?target=ulfr.io&rescan=true'
```

**Parameters**:

* `target` is the FQDN of the target site. eg. `google.com`. Do not use protocol handlers or query strings.
* `rescan` asks for a rescan of the target when set to true.

**Output**: a `json` document containing the Scan ID.

**Caching**: When `rescan` is not `true`, if a scan of the target was done over the last 24 hours, the scan ID is returned. Use `rescan=true` to force a rescan within 24 hours of the previous scan.

**Rate Limits**: Each target can only be scanned every 3 minutes with `rescan=true`.

#### GET /api/v1/results

Retrieve scan results by its ID.

```bash
curl https://tls-observatory.services.mozilla.com/api/v1/results?id=12302333
```

**Parameters**:

* `id` is the Scan ID

**Output**: a `json` document containing the scan results and the ID of the end-entity certificate.

#### GET /api/v1/certificate

Retrieve a certificate by its ID.

```bash
curl https://tls-observatory.services.mozilla.com/api/v1/certificate?id=1
```

**Parameters**:

* `id` is the Certificate ID
* `sha256` the hexadecimal checksum of the DER certificate (only if `id` is not
  provided)

**Output**: a `json` document containing the parsed certificate and its raw X509 version encoded with base64.

#### POST /api/v1/certificate

Publish a certificate.

```bash
curl -X POST -F certificate=@example.pem https://tls-observatory.services.mozilla.com/api/v1/certificate
```

**Parameters**:

* `certificate` is a POST multipart/form-data parameter that contains the PEM encoded certificate.

**Output**: a `json` document containing the parsed certificate and its raw X509 version encoded with base64.

**Caching**: Certificates are only stored once. The database uses the SHA256 hash of the DER (binary) certificate to identify duplicates. Posting a certificate already stored in database returns the stored version. 

#### GET /api/v1/paths

Retrieve the paths from a certificate to one of multiple roots.

```bash
curl https://tls-observatory.services.mozilla.com/api/v1/paths?id=1
```

**Parameters**:

* `id` is the ID of the certificate to start the path at.
* `sha256` the hexadecimal checksum of the DER certificate (only if `id` is not
  provided)

**Output**: a `json` document containing the paths document. Each entry in the path contains the current certificate and an array of parents, if any exist.

#### GET /api/v1/truststore

Retrieve all the certificates in a given truststore.

```bash
curl https://tls-observatory.services.mozilla.com/api/v1/truststore?store=mozilla&format=pem
```

**Parameters**:

* `store` is the store to retrieve certificates from. "mozilla", "android", "apple", "microsoft" and "ubuntu" are allowed.
* `format`, either "pem" or "json". 

**Output**: if `format` is pem, a series of PEM-format certificates. If `format` is json, a json array of certificate objects, each with the same format of `/api/v1/certificate`.

### Database Queries

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
## Authors

 * Dimitris Bachtis
 * Julien Vehent

## License

 * Mozilla Public License Version 2.0
