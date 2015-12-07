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
GO 			:= GOOS=$(OS) GOARCH=$(ARCH) GO15VENDOREXPERIMENT=1 go
GOGETTER	:= GOPATH=$(shell pwd)/.tmpdeps go get -d
GOLDFLAGS	:= -ldflags "-X main.version=$(BUILDREV)"
GOCFLAGS	:=
MKDIR		:= mkdir
INSTALL		:= install

all: tlsobs-scanner tlsobs-api

tlsobs-scanner:
	echo building TLS Observatory Scanner for $(OS)/$(ARCH)
	$(MKDIR) -p $(BINDIR)
	$(GO) build $(GOOPTS) -o $(BINDIR)/tlsobs-scanner-$(BUILDREV)$(BINSUFFIX) $(GOLDFLAGS) github.com/mozilla/tls-observatory/tlsobs-scanner
	[ -x "$(BINDIR)/tlsobs-scanner-$(BUILDREV)$(BINSUFFIX)" ] && echo SUCCESS && exit 0

tlsobs-api:
	echo building tlsobs-api for $(OS)/$(ARCH)
	$(MKDIR) -p $(BINDIR)
	$(GO) build $(GOOPTS) -o $(BINDIR)/tlsobs-api-$(BUILDREV)$(BINSUFFIX) $(GOLDFLAGS) github.com/mozilla/tls-observatory/tlsobs-api
	[ -x "$(BINDIR)/tlsobs-api-$(BUILDREV)$(BINSUFFIX)" ] && echo SUCCESS && exit 0

go_vendor_dependencies:
	$(GOGETTER) github.com/Sirupsen/logrus
	$(GOGETTER) gopkg.in/gcfg.v1
	$(GOGETTER) github.com/jvehent/gozdef
	$(GOGETTER) github.com/lib/pq
	$(GOGETTER) github.com/gorilla/mux
	$(GOGETTER) github.com/gorilla/context
	echo 'removing .git from vendored pkg and moving them to vendor'
	find .tmpdeps/src -type d -name ".git" ! -name ".gitignore" -exec rm -rf {} \; || exit 0
	cp -ar .tmpdeps/src/* vendor/
	rm -rf .tmpdeps

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
	$(INSTALL) -D -m 0755 $(BINDIR)/SSLv3Trigger-$(BUILDREV)$(BINSUFFIX) tmppkg/opt/observer/bin/SSLv3Trigger
	$(INSTALL) -D -m 0755 $(BINDIR)/39monthsTrigger-$(BUILDREV)$(BINSUFFIX) tmppkg/opt/observer/bin/39monthsTrigger
	$(INSTALL) -D -m 0755 $(BINDIR)/mozillaExpiring7DaysTrigger-$(BUILDREV)$(BINSUFFIX) tmppkg/opt/observer/bin/mozillaExpiring7DaysTrigger
	$(INSTALL) -D -m 0755 $(BINDIR)/mozillaWildcardTrigger-$(BUILDREV)$(BINSUFFIX) tmppkg/opt/observer/bin/mozillaWildcardTrigger
# configuration files
	$(INSTALL) -D -m 0755 conf/certanalyzer.cfg tmppkg/etc/observer
	$(INSTALL) -D -m 0755 conf/certretriever.cfg tmppkg/etc/observer
	$(INSTALL) -D -m 0755 conf/tlsanalyzer.cfg tmppkg/etc/observer
	$(INSTALL) -D -m 0755 conf/tlsretriever.cfg tmppkg/etc/observer
	$(INSTALL) -D -m 0755 conf/trigger.cfg tmppkg/etc/observer
# init scripts
	$(INSTALL) -D -m 0755 conf/tlsobserver-certanalyzer.conf tmppkg/etc/init
	$(INSTALL) -D -m 0755 conf/tlsobserver-certretriever.conf tmppkg/etc/init
	$(INSTALL) -D -m 0755 conf/tlsobserver-tlsanalyzer.conf tmppkg/etc/init
	$(INSTALL) -D -m 0755 conf/tlsobserver-tlsretriever.conf tmppkg/etc/init
	$(INSTALL) -D -m 0755 conf/tlsobserver-sslv3trigger.conf tmppkg/etc/init
	$(INSTALL) -D -m 0755 conf/tlsobserver-39monthstrigger.conf tmppkg/etc/init
	$(INSTALL) -D -m 0755 conf/tlsobserver-mozillaexpiring7daystrigger.conf tmppkg/etc/init
	$(INSTALL) -D -m 0755 conf/tlsobserver-mozillawildcardtrigger.conf tmppkg/etc/init
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
		-m "Mozilla OpSec" --url https://github.com/mozilla/tls-observatory --architecture $(FPMARCH) -v $(BUILDREV) \
		-s dir -t deb .

test:
	$(GO) test github.com/mozilla/tls-observatory/worker/mozillaEvaluationWorker/

clean:
	rm -rf bin
	find src/ -maxdepth 1 -mindepth 1 -name github* -exec rm -rf {} \;

.PHONY: clean
