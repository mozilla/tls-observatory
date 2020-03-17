# Certificate Transparency Log Monitor

[![Build Status](https://travis-ci.org/google/monologue.svg?branch=master)](https://travis-ci.org/google/monologue)
[![Go Report Card](https://goreportcard.com/badge/github.com/google/monologue)](https://goreportcard.com/report/github.com/google/monologue)
[![GolangCI](https://golangci.com/badges/github.com/google/monologue.svg)](https://golangci.com/r/github.com/google/monologue)
[![codecov.io](http://codecov.io/github/google/monologue/coverage.svg)](http://codecov.io/github/google/monologue)
[![GoDoc](https://godoc.org/github.com/google/monologue?status.svg)](https://godoc.org/github.com/google/monologue)

This repository contains the source code for the monitor that checks that
Certificate Transparency Logs are complying with [RFC 6962](https://tools.ietf.org/html/rfc6962)
and the [Chromium Certificate Transparency Log Policy](https://github.com/chromium/ct-policy).

This project is currently in development and so may be subject to significant
change.


## Working on the Code

The [`scripts/presubmit.sh`](scripts/presubmit.sh) script runs various tools
and tests over the codebase.

```bash
# Install golangci-lint
go get -u github.com/golangci/golangci-lint/cmd/golangci-lint
cd $GOPATH/src/github.com/golangci/golangci-lint/cmd/golangci-lint
go install -ldflags "-X 'main.version=$(git describe --tags)' -X 'main.commit=$(git rev-parse --short HEAD)' -X 'main.date=$(date)'"
cd -
# Run build, test and linters
./scripts/presubmit.sh
# Or just run the linters alone
golangci-lint run
```

