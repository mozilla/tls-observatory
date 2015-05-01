# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

BUILDREF	:= $(shell git log --pretty=format:'%h' -n 1)
BUILDDATE	:= $(shell date +%Y%m%d)
BUILDENV	:= dev
BUILDREV	:= $(BUILDDATE)+$(BUILDREF).$(BUILDENV)

# Supported OSes: linux darwin windows
# Supported ARCHes: 386 amd64
OS			:= linux
ARCH		:= amd64

ifeq ($(ARCH),amd64)
	FPMARCH := x86_64
endif
ifeq ($(ARCH),386)
	FPMARCH := i386
endif
ifeq ($(OS),windows)
	BINSUFFIX   := ".exe"
else
	BINSUFFIX	:= ""
endif
PREFIX		:= /usr/local/
DESTDIR		:= /
BINDIR		:= bin/$(OS)/$(ARCH)
GCC			:= gcc
CFLAGS		:=
LDFLAGS		:=
GOOPTS		:= -tags netgo
GO 			:= GOPATH=$(shell go env GOROOT)/bin:$(shell pwd) GOOS=$(OS) GOARCH=$(ARCH) go
GOGETTER	:= GOPATH=$(shell pwd) GOOS=$(OS) GOARCH=$(ARCH) go get -u
GOLDFLAGS	:= -ldflags "-X main.version $(BUILDREV)"
GOCFLAGS	:=
MKDIR		:= mkdir
INSTALL		:= install

all: go_get_deps certRetriever certAnalyzer tlsRetriever tlsAnalyzer webapi retrieveTLSInfo rescanDomains SSLv3Analyzer 39monthAnalyzer

rescanDomains:
	echo building rescanDomains for $(OS)/$(ARCH)
	$(MKDIR) -p $(BINDIR)
	$(GO) build $(GOOPTS) -o $(BINDIR)/rescanDomains-$(BUILDREV)$(BINSUFFIX) $(GOLDFLAGS) src/rescanDomains.go
	[ -x "$(BINDIR)/rescanDomains-$(BUILDREV)$(BINSUFFIX)" ] && echo SUCCESS && exit 0

retrieveTLSInfo:
	echo building retrieveTLSInfo for $(OS)/$(ARCH)
	$(MKDIR) -p $(BINDIR)
	$(GO) build $(GOOPTS) -o $(BINDIR)/retrieveTLSInfo-$(BUILDREV)$(BINSUFFIX) $(GOLDFLAGS) src/retrieveTLSInfo.go
	[ -x "$(BINDIR)/retrieveTLSInfo-$(BUILDREV)$(BINSUFFIX)" ] && echo SUCCESS && exit 0

certRetriever:
	echo building certRetriever for $(OS)/$(ARCH)
	$(MKDIR) -p $(BINDIR)
	$(GO) build $(GOOPTS) -o $(BINDIR)/certRetriever-$(BUILDREV)$(BINSUFFIX) $(GOLDFLAGS) certRetriever
	[ -x "$(BINDIR)/certRetriever-$(BUILDREV)$(BINSUFFIX)" ] && echo SUCCESS && exit 0

certAnalyzer:
	echo building certAnalyzer for $(OS)/$(ARCH)
	$(MKDIR) -p $(BINDIR)
	$(GO) build $(GOOPTS) -o $(BINDIR)/certAnalyzer-$(BUILDREV)$(BINSUFFIX) $(GOLDFLAGS) certAnalyzer
	[ -x "$(BINDIR)/certAnalyzer-$(BUILDREV)$(BINSUFFIX)" ] && echo SUCCESS && exit 0

tlsRetriever:
	echo building tlsRetriever for $(OS)/$(ARCH)
	$(MKDIR) -p $(BINDIR)
	$(GO) build $(GOOPTS) -o $(BINDIR)/tlsRetriever-$(BUILDREV)$(BINSUFFIX) $(GOLDFLAGS) tlsRetriever
	[ -x "$(BINDIR)/tlsRetriever-$(BUILDREV)$(BINSUFFIX)" ] && echo SUCCESS && exit 0

tlsAnalyzer:
	echo building tlsAnalyzer for $(OS)/$(ARCH)
	$(MKDIR) -p $(BINDIR)
	$(GO) build $(GOOPTS) -o $(BINDIR)/tlsAnalyzer-$(BUILDREV)$(BINSUFFIX) $(GOLDFLAGS) tlsAnalyzer
	[ -x "$(BINDIR)/tlsAnalyzer-$(BUILDREV)$(BINSUFFIX)" ] && echo SUCCESS && exit 0

SSLv3Analyzer:
	echo building SSLv3Analyzer for $(OS)/$(ARCH)
	$(MKDIR) -p $(BINDIR)
	$(GO) build $(GOOPTS) -o $(BINDIR)/SSLv3Analyzer-$(BUILDREV)$(BINSUFFIX) $(GOLDFLAGS) SSLv3Analyzer
	[ -x "$(BINDIR)/SSLv3Analyzer-$(BUILDREV)$(BINSUFFIX)" ] && echo SUCCESS && exit 0

39monthAnalyzer:
	echo building 39monthAnalyzer for $(OS)/$(ARCH)
	$(MKDIR) -p $(BINDIR)
	$(GO) build $(GOOPTS) -o $(BINDIR)/39monthAnalyzer-$(BUILDREV)$(BINSUFFIX) $(GOLDFLAGS) 39monthAnalyzer
	[ -x "$(BINDIR)/39monthAnalyzer-$(BUILDREV)$(BINSUFFIX)" ] && echo SUCCESS && exit 0

webapi:
	echo building web-api for $(OS)/$(ARCH)
	$(MKDIR) -p $(BINDIR)
	$(GO) build $(GOOPTS) -o $(BINDIR)/web-api-$(BUILDREV)$(BINSUFFIX) $(GOLDFLAGS) web-api
	[ -x "$(BINDIR)/web-api-$(BUILDREV)$(BINSUFFIX)" ] && echo SUCCESS && exit 0

go_get_deps_into_system:
	make GOGETTER="go get -u" go_get_deps

go_get_deps:
	$(GOGETTER) github.com/streadway/amqp
	$(GOGETTER) github.com/mattbaird/elastigo/lib
	$(GOGETTER) github.com/gorilla/mux
	$(GOGETTER) code.google.com/p/gcfg

deb-pkg: all
	rm -fr tmppkg
	$(MKDIR) -p tmppkg/opt/observer/bin tmppkg/etc/observer/truststores tmppkg/etc/init/
# binaries
	$(INSTALL) -D -m 0755 $(BINDIR)/certRetriever-$(BUILDREV)$(BINSUFFIX) tmppkg/opt/observer/bin/certRetriever
	$(INSTALL) -D -m 0755 $(BINDIR)/certAnalyzer-$(BUILDREV)$(BINSUFFIX) tmppkg/opt/observer/bin/certAnalyzer
	$(INSTALL) -D -m 0755 $(BINDIR)/tlsRetriever-$(BUILDREV)$(BINSUFFIX) tmppkg/opt/observer/bin/tlsRetriever
	$(INSTALL) -D -m 0755 $(BINDIR)/tlsAnalyzer-$(BUILDREV)$(BINSUFFIX) tmppkg/opt/observer/bin/tlsAnalyzer
	$(INSTALL) -D -m 0755 $(BINDIR)/web-api-$(BUILDREV)$(BINSUFFIX) tmppkg/opt/observer/bin/web-api
	$(INSTALL) -D -m 0755 $(BINDIR)/retrieveTLSInfo-$(BUILDREV)$(BINSUFFIX) tmppkg/opt/observer/bin/retrieveTLSInfo
	$(INSTALL) -D -m 0755 $(BINDIR)/rescanDomains-$(BUILDREV)$(BINSUFFIX) tmppkg/opt/observer/bin/rescanDomains
	$(INSTALL) -D -m 0755 $(BINDIR)/SSLv3Analyzer-$(BUILDREV)$(BINSUFFIX) tmppkg/opt/observer/bin/SSLv3Analyzer
	$(INSTALL) -D -m 0755 $(BINDIR)/39monthAnalyzer-$(BUILDREV)$(BINSUFFIX) tmppkg/opt/observer/bin/39monthAnalyzer
# configuration files
	$(INSTALL) -D -m 0755 conf/certanalyzer.cfg tmppkg/etc/observer
	$(INSTALL) -D -m 0755 conf/certretriever.cfg tmppkg/etc/observer
	$(INSTALL) -D -m 0755 conf/tlsanalyzer.cfg tmppkg/etc/observer
	$(INSTALL) -D -m 0755 conf/tlsretriever.cfg tmppkg/etc/observer
# init scripts
	$(INSTALL) -D -m 0755 conf/tlsobserver-certanalyzer.conf tmppkg/etc/init
	$(INSTALL) -D -m 0755 conf/tlsobserver-certretriever.conf tmppkg/etc/init
	$(INSTALL) -D -m 0755 conf/tlsobserver-tlsanalyzer.conf tmppkg/etc/init
	$(INSTALL) -D -m 0755 conf/tlsobserver-tlsretriever.conf tmppkg/etc/init
# truststores
	$(INSTALL) -D -m 0755 CA_AOSP.crt tmppkg/etc/observer/truststores
	$(INSTALL) -D -m 0755 CA_apple_10.10.0.crt tmppkg/etc/observer/truststores
	$(INSTALL) -D -m 0755 CA_apple_10.8.5.crt tmppkg/etc/observer/truststores
	$(INSTALL) -D -m 0755 CA_apple_10.9.5.crt tmppkg/etc/observer/truststores
	$(INSTALL) -D -m 0755 CA_java.crt tmppkg/etc/observer/truststores
	$(INSTALL) -D -m 0755 CA_microsoft.crt tmppkg/etc/observer/truststores
	$(INSTALL) -D -m 0755 CA_mozilla_nss.crt tmppkg/etc/observer/truststores
	$(INSTALL) -D -m 0755 CA_ubuntu_12.04.crt tmppkg/etc/observer/truststores
# list of top 1m sites from alexas
	$(INSTALL) -D -m 0755 top-1m.csv tmppkg/etc/observer/top-1m.csv
# elasticsearch schemas
	$(INSTALL) -D -m 0755 cert_schema.json tmppkg/etc/observer/cert_schema.json
	$(INSTALL) -D -m 0755 conn_schema.json tmppkg/etc/observer/conn_schema.json
# make a debian package
	fpm -C tmppkg -n mozilla-tls-observer --license GPL --vendor mozilla --description "Mozilla TLS Observer" \
		-m "Mozilla OpSec" --url https://github.com/mozilla/TLS-Observer --architecture $(FPMARCH) -v $(BUILDREV) \
		-s dir -t deb .

clean:
	rm -rf bin
	find src/ -maxdepth 1 -mindepth 1 -name github* -exec rm -rf {} \;

.PHONY: clean
