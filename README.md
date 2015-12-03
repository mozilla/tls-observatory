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
