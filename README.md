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

##Authors##

 * Dimitris Bachtis
 * Julien Vehent

##License##

 * Mozilla Public License Version 2.0
