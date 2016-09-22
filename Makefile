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
GOOPTS		:=
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
	$(GO) build $(GOOPTS) -o $(GOPATH)/bin/tlsobs-scanner$(BINSUFFIX) $(GOLDFLAGS) github.com/mozilla/tls-observatory/tlsobs-scanner

tlsobs-api:
	echo building tlsobs-api for $(OS)/$(ARCH)
	$(MKDIR) -p $(BINDIR)
	$(GO) build $(GOOPTS) -o $(GOPATH)/bin/tlsobs-api$(BINSUFFIX) $(GOLDFLAGS) github.com/mozilla/tls-observatory/tlsobs-api

tlsobs:
	echo building tlsobs client for $(OS)/$(ARCH)
	$(MKDIR) -p $(BINDIR)
	$(GO) build $(GOOPTS) -o $(GOPATH)/bin/tlsobs$(BINSUFFIX) $(GOLDFLAGS) github.com/mozilla/tls-observatory/tlsobs

tlsobs-runner:
	echo building tlsobs-runner for $(OS)/$(ARCH)
	$(MKDIR) -p $(BINDIR)
	$(GO) build $(GOOPTS) -o $(GOPATH)/bin/tlsobs-runner$(BINSUFFIX) $(GOLDFLAGS) github.com/mozilla/tls-observatory/tlsobs-runner

vendor:
	govend -u

test:
	$(GO) test github.com/mozilla/tls-observatory/worker/mozillaEvaluationWorker/
	$(GO) test github.com/mozilla/tls-observatory/tlsobs-runner

.PHONY: all test clean tlsobs-scanner tlsobs-api tlsobs-runner tlsobs vendor
