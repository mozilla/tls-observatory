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

all: go_get_deps certRetriever certAnalyser tlsRetriever tlsAnalyser webapi retrieveTLSInfo rescanDomains

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

certAnalyser:
	echo building certAnalyser for $(OS)/$(ARCH)
	$(MKDIR) -p $(BINDIR)
	$(GO) build $(GOOPTS) -o $(BINDIR)/certAnalyzer-$(BUILDREV)$(BINSUFFIX) $(GOLDFLAGS) certAnalyser
	[ -x "$(BINDIR)/certAnalyzer-$(BUILDREV)$(BINSUFFIX)" ] && echo SUCCESS && exit 0

tlsRetriever:
	echo building tlsRetriever for $(OS)/$(ARCH)
	$(MKDIR) -p $(BINDIR)
	$(GO) build $(GOOPTS) -o $(BINDIR)/tlsRetriever-$(BUILDREV)$(BINSUFFIX) $(GOLDFLAGS) tlsRetriever
	[ -x "$(BINDIR)/tlsRetriever-$(BUILDREV)$(BINSUFFIX)" ] && echo SUCCESS && exit 0

tlsAnalyser:
	echo building tlsAnalyser for $(OS)/$(ARCH)
	$(MKDIR) -p $(BINDIR)
	$(GO) build $(GOOPTS) -o $(BINDIR)/tlsAnalyser-$(BUILDREV)$(BINSUFFIX) $(GOLDFLAGS) tlsAnalyser
	[ -x "$(BINDIR)/tlsAnalyser-$(BUILDREV)$(BINSUFFIX)" ] && echo SUCCESS && exit 0

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
	$(INSTALL) -D -m 0755 $(BINDIR)/certRetriever-$(BUILDREV)$(BINSUFFIX) tmppkg/opt/observer/bin/certRetriever
	$(INSTALL) -D -m 0755 $(BINDIR)/certAnalyzer-$(BUILDREV)$(BINSUFFIX) tmppkg/opt/observer/bin/certAnalyzer
	$(INSTALL) -D -m 0755 $(BINDIR)/tlsRetriever-$(BUILDREV)$(BINSUFFIX) tmppkg/opt/observer/bin/tlsRetriever
	$(INSTALL) -D -m 0755 $(BINDIR)/tlsAnalyzer-$(BUILDREV)$(BINSUFFIX) tmppkg/opt/observer/bin/tlsAnalyzer
	$(INSTALL) -D -m 0755 $(BINDIR)/web-api-$(BUILDREV)$(BINSUFFIX) tmppkg/opt/observer/bin/web-api
	$(INSTALL) -D -m 0755 $(BINDIR)/retrieveTLSInfo-$(BUILDREV)$(BINSUFFIX) tmppkg/opt/observer/bin/retrieveTLSInfo
	$(INSTALL) -D -m 0755 $(BINDIR)/rescanDomains-$(BUILDREV)$(BINSUFFIX) tmppkg/opt/observer/bin/rescanDomains
	$(INSTALL) -D -m 0755 conf/retriever.cfg tmppkg/etc/observer/retriever.cfg.inc
	$(INSTALL) -D -m 0755 conf/tlsobserver-retriever.conf tmppkg/etc/init/tlsobserver-retriever.conf
	$(INSTALL) -D -m 0755 conf/analyzer.cfg tmppkg/etc/observer/analyzer.cfg.inc
	$(INSTALL) -D -m 0755 conf/tlsobserver-analyzer.conf tmppkg/etc/init/tlsobserver-analyzer.conf
	$(INSTALL) -D -m 0755 CA_apple_10.10.0.crt tmppkg/etc/observer/truststores
	$(INSTALL) -D -m 0755 CA_apple_10.8.5.crt tmppkg/etc/observer/truststores
	$(INSTALL) -D -m 0755 CA_apple_10.9.5.crt tmppkg/etc/observer/truststores
	$(INSTALL) -D -m 0755 CA_java.crt tmppkg/etc/observer/truststores
	$(INSTALL) -D -m 0755 CA_microsoft.crt tmppkg/etc/observer/truststores
	$(INSTALL) -D -m 0755 CA_mozilla_nss.crt tmppkg/etc/observer/truststores
	$(INSTALL) -D -m 0755 CA_ubuntu_12.04.crt tmppkg/etc/observer/truststores
	$(INSTALL) -D -m 0755 top-1m.csv tmppkg/etc/observer/top-1m.csv
	$(INSTALL) -D -m 0755 certificates_schema.json tmppkg/etc/observer/certificates_schema.json
	fpm -C tmppkg -n mozilla-tls-observer --license GPL --vendor mozilla --description "Mozilla TLS Observer" \
		-m "Mozilla OpSec" --url https://github.com/mozilla/TLS-Observer --architecture $(FPMARCH) -v $(BUILDREV) \
		-s dir -t deb .

clean:
	rm -rf bin
	find src/ -maxdepth 1 -mindepth 1 -name github* -exec rm -rf {} \;

.PHONY: clean
