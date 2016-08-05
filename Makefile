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

all: test tlsobs-scanner tlsobs-api tlsobs tlsobs-runner

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

tlsobs:
	echo building tlsobs client for $(OS)/$(ARCH)
	$(MKDIR) -p $(BINDIR)
	$(GO) build $(GOOPTS) -o $(BINDIR)/tlsobs-$(BUILDREV)$(BINSUFFIX) $(GOLDFLAGS) github.com/mozilla/tls-observatory/tlsobs
	[ -x "$(BINDIR)/tlsobs-$(BUILDREV)$(BINSUFFIX)" ] && echo SUCCESS && exit 0

tlsobs-runner:
	echo building tlsobs-runner for $(OS)/$(ARCH)
	$(MKDIR) -p $(BINDIR)
	$(GO) build $(GOOPTS) -o $(BINDIR)/tlsobs-runner-$(BUILDREV)$(BINSUFFIX) $(GOLDFLAGS) github.com/mozilla/tls-observatory/tlsobs-runner
	[ -x "$(BINDIR)/tlsobs-runner-$(BUILDREV)$(BINSUFFIX)" ] && echo SUCCESS && exit 0

go_vendor_dependencies:
	$(GOGETTER) github.com/Sirupsen/logrus
	$(GOGETTER) gopkg.in/gcfg.v1
	$(GOGETTER) github.com/jvehent/gozdef
	$(GOGETTER) github.com/lib/pq
	$(GOGETTER) github.com/gorilla/mux
	$(GOGETTER) github.com/gorilla/context
	$(GOGETTER) github.com/gorhill/cronexpr
	$(GOGETTER) gopkg.in/yaml.v2
	$(GOGETTER) github.com/fatih/color
	echo 'removing .git from vendored pkg and moving them to vendor'
	find .tmpdeps/src -name ".git" ! -name ".gitignore" -exec rm -rf {} \; || exit 0
	[ -d vendor ] && git rm -rf vendor/ || exit 0
	mkdir vendor/ || exit 0
	cp -ar .tmpdeps/src/* vendor/
	git add vendor/
	rm -rf .tmpdeps

test:
	$(GO) test github.com/mozilla/tls-observatory/worker/mozillaEvaluationWorker/
	$(GO) test github.com/mozilla/tls-observatory/tlsobs-runner

.PHONY: all test clean tlsobs-scanner tlsobs-api tlsobs-runner tlsobs
