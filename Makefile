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
GO 			:= GOPATH=$(shell go env GOROOT)/bin:$(shell pwd) GOOS=$(OS) GOARCH=$(ARCH) go
GOGETTER	:= GOPATH=$(shell pwd) GOOS=$(OS) GOARCH=$(ARCH) go get -u
GOLDFLAGS	:= -ldflags "-X main.version $(BUILDREV)"
GOCFLAGS	:=
MKDIR		:= mkdir
INSTALL		:= install

all: go_get_deps retrieverWorker

certRetriever:
	echo building retrieverWorker for $(OS)/$(ARCH)
	$(MKDIR) -p $(BINDIR)
	$(GO) build $(GOOPTS) -o $(BINDIR)/retrieverWorker-$(BUILDREV)$(BINSUFFIX) $(GOLDFLAGS) certRetriever
	[ -x "$(BINDIR)/retrieverWorker-$(BUILDREV)$(BINSUFFIX)" ] && echo SUCCESS && exit 0

certAnalyser:
	echo building certAnalyser for $(OS)/$(ARCH)
	$(MKDIR) -p $(BINDIR)
	$(GO) build $(GOOPTS) -o $(BINDIR)/certAnalyser-$(BUILDREV)$(BINSUFFIX) $(GOLDFLAGS) certAnalyser
	[ -x "$(BINDIR)/certAnalyser-$(BUILDREV)$(BINSUFFIX)" ] && echo SUCCESS && exit 0


go_get_deps_into_system:
	make GOGETTER="go get -u" go_get_deps

go_get_deps:
	$(GOGETTER) github.com/streadway/amqp
	$(GOGETTER) github.com/mattbaird/elastigo/lib
	$(GOGETTER) github.com/gorilla/mux

clean:
	rm -rf bin
	find src/ -maxdepth 1 -mindepth 1 -name github* -exec rm -rf {} \;

.PHONY: clean
