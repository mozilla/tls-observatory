PROJS = scribe scribecmd evrtest ubuntu-cve-tracker parse-nasltokens \
	scribevulnpolicy
GO = GO15VENDOREXPERIMENT=1 go
GOGETTER = GOPATH=$(shell pwd)/.tmpdeps go get -d
GOLINT = golint

all: $(PROJS) runtests

ubuntu-cve-tracker:
	$(GO) install github.com/mozilla/scribe/ubuntu-cve-tracker

parse-nasltokens:
	$(GO) install github.com/mozilla/scribe/parse-nasltokens

evrtest:
	$(GO) install github.com/mozilla/scribe/evrtest

scribe:
	$(GO) install github.com/mozilla/scribe
	$(GO) install github.com/mozilla/scribe/vulnpolicy

scribecmd:
	$(GO) install github.com/mozilla/scribe/scribecmd

scribevulnpolicy:
	$(GO) install github.com/mozilla/scribe/scribevulnpolicy

runtests: scribetests gotests

gotests:
	$(GO) test -v -covermode=count -coverprofile=coverage.out github.com/mozilla/scribe

showcoverage: gotests
	$(GO) tool cover -html=coverage.out

scribetests: $(PROJS)
	cd test && SCRIBECMD=$$(which scribecmd) EVRTESTCMD=$$(which evrtest) $(MAKE) runtests

lint:
	$(GOLINT) $(PROJECT)

vet:
	$(GO) vet $(PROJECT)

go_vendor_dependencies:
	$(GOGETTER) gopkg.in/yaml.v2
	echo 'removing .git from vendored pkg and moving them to vendor'
	find .tmpdeps/src -name ".git" ! -name ".gitignore" -exec rm -rf {} \; || exit 0
	[ -d vendor ] && git rm -rf vendor/ || exit 0
	mkdir vendor/ || exit 0
	cp -ar .tmpdeps/src/* vendor/
	git add vendor/
	rm -rf .tmpdeps

clean:
	rm -rf pkg
	rm -f bin/*
	cd test && $(MAKE) clean

.PHONY: $(PROJS) runtests gotests showcoverage scribetests lint vet clean
