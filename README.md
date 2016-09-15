# Mozilla TLS Observatory

## Getting started with the scanner

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
Scanning twitter.com (id 10131248)
Retrieving cached results from 23h31m55.708675882s ago. To run a new scan, use '-r'.

--- Certificate ---
Subject  C=US, O=Twitter, Inc., OU=Twitter Security, CN=twitter.com	
SubjectAlternativeName
- twitter.com
- www.twitter.com
Issuer   C=US, O=Symantec Corporation, OU=Symantec Trust Network, CN=Symantec Class 3 EV SSL CA - G3
Validity 2014-09-10T00:00:00Z to 2016-05-09T23:59:59Z
CA       false
SHA1     ADD53F6680FE66E383CBAC3E60922E3B4C412BED
SHA256   1B58D2C443AE4BD70B9B26EB6BF41CEE43CBA95D9DC65F54A0003E4DE9CDBAF6
SigAlg   SHA256WithRSA


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
* Mozilla evaluation: intermediate
  - for old level: sha256WithRSAEncryption is not an old certificate signature, use sha1WithRSAEncryption
  - for old level: consider adding ciphers ECDHE-ECDSA-CHACHA20-POLY1305, ECDHE-RSA-CHACHA20-POLY1305, ECDHE-ECDSA-AES128-GCM-SHA256, ECDHE-ECDSA-AES256-GCM-SHA384, DHE-RSA-AES128-GCM-SHA256, DHE-DSS-AES128-GCM-SHA256, DHE-DSS-AES256-GCM-SHA384, DHE-RSA-AES256-GCM-SHA384, ECDHE-ECDSA-AES128-SHA256, ECDHE-ECDSA-AES128-SHA, ECDHE-ECDSA-AES256-SHA384, ECDHE-ECDSA-AES256-SHA, DHE-RSA-AES128-SHA256, DHE-RSA-AES128-SHA, DHE-DSS-AES128-SHA256, DHE-RSA-AES256-SHA256, DHE-DSS-AES256-SHA, DHE-RSA-AES256-SHA, ECDHE-ECDSA-DES-CBC3-SHA, EDH-RSA-DES-CBC3-SHA, DHE-DSS-AES256-SHA256, DHE-DSS-AES128-SHA, DHE-RSA-CHACHA20-POLY1305, ECDHE-RSA-CAMELLIA256-SHA384, ECDHE-ECDSA-CAMELLIA256-SHA384, DHE-RSA-CAMELLIA256-SHA256, DHE-DSS-CAMELLIA256-SHA256, DHE-RSA-CAMELLIA256-SHA, DHE-DSS-CAMELLIA256-SHA, CAMELLIA256-SHA256, CAMELLIA256-SHA, ECDHE-RSA-CAMELLIA128-SHA256, ECDHE-ECDSA-CAMELLIA128-SHA256, DHE-RSA-CAMELLIA128-SHA256, DHE-DSS-CAMELLIA128-SHA256, DHE-RSA-CAMELLIA128-SHA, DHE-DSS-CAMELLIA128-SHA, CAMELLIA128-SHA256, CAMELLIA128-SHA, DHE-RSA-SEED-SHA, DHE-DSS-SEED-SHA, SEED-SHA
  - for old level: add protocols SSLv3
  - for old level: consider enabling OCSP stapling
  - for intermediate level: consider adding ciphers ECDHE-ECDSA-CHACHA20-POLY1305, ECDHE-RSA-CHACHA20-POLY1305, ECDHE-ECDSA-AES128-GCM-SHA256, ECDHE-ECDSA-AES256-GCM-SHA384, DHE-RSA-AES128-GCM-SHA256, DHE-RSA-AES256-GCM-SHA384, ECDHE-ECDSA-AES128-SHA256, ECDHE-ECDSA-AES128-SHA, ECDHE-ECDSA-AES256-SHA384, ECDHE-ECDSA-AES256-SHA, DHE-RSA-AES128-SHA256, DHE-RSA-AES128-SHA, DHE-RSA-AES256-SHA256, DHE-RSA-AES256-SHA, ECDHE-ECDSA-DES-CBC3-SHA, EDH-RSA-DES-CBC3-SHA
  - for intermediate level: increase priority of ECDHE-RSA-AES256-GCM-SHA384 over ECDHE-RSA-AES128-SHA
  - for intermediate level: increase priority of AES256-GCM-SHA384 over AES128-SHA
  - for intermediate level: increase priority of ECDHE-RSA-DES-CBC3-SHA over AES256-SHA
  - for intermediate level: fix ciphersuite ordering, use recommended intermediate ciphersuite
  - for modern level: remove ciphersuites ECDHE-RSA-AES128-SHA, ECDHE-RSA-AES256-SHA, AES128-GCM-SHA256, AES128-SHA256, AES128-SHA, AES256-GCM-SHA384, AES256-SHA256, AES256-SHA, ECDHE-RSA-DES-CBC3-SHA, DES-CBC3-SHA
  - for modern level: consider adding ciphers ECDHE-ECDSA-AES256-GCM-SHA384, ECDHE-ECDSA-CHACHA20-POLY1305, ECDHE-RSA-CHACHA20-POLY1305, ECDHE-ECDSA-AES128-GCM-SHA256, ECDHE-ECDSA-AES256-SHA384, ECDHE-ECDSA-AES128-SHA256
  - for modern level: remove protocols TLSv1, TLSv1.1
  - oldest clients: Firefox 1, Chrome 1, IE 7, Opera 5, Safari 1, Windows XP IE8, Android 2.3, Java 7
```

The analysis at the end tell you what need to be changed to reach the old, intermediate or modern level. We recommend to target the intermediate level by default, and modern if you don't care about old clients.

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
go get github.com/mozilla/tls-observatory/tlsobs-scanner
go get github.com/mozilla/tls-observatory/tlsobs-api
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

#### tlsobs-runner
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
