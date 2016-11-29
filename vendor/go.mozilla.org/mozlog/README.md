# mozlog [![GoDoc](https://godoc.org/go.mozilla.org/mozlog?status.svg)](https://godoc.org/go.mozilla.org/mozlog) [![Build Status](https://travis-ci.org/mozilla-services/go-mozlog.svg?branch=master)](https://travis-ci.org/mozilla-services/go-mozlog)
A logging library which conforms to Mozilla's logging standard.

## Example Usage
```
import "go.mozilla.org/mozlog"

func init() {
    mozlog.Logger.LoggerName = "ApplicationName"
}
```
