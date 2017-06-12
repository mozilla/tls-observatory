package main

import (
	_ "github.com/mozilla/tls-observatory/worker/evCheckerWorker"
	_ "github.com/mozilla/tls-observatory/worker/mozillaEvaluationWorker"
	_ "github.com/mozilla/tls-observatory/worker/mozillaGradingWorker"
	_ "github.com/mozilla/tls-observatory/worker/sslLabsClientSupport"
	_ "github.com/mozilla/tls-observatory/worker/top1m"
)
