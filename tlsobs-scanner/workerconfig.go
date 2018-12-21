package main

import (
	_ "github.com/mozilla/tls-observatory/worker/awsCertlint"
	_ "github.com/mozilla/tls-observatory/worker/caaWorker"
	_ "github.com/mozilla/tls-observatory/worker/crlWorker"
	_ "github.com/mozilla/tls-observatory/worker/evCheckerWorker"
	_ "github.com/mozilla/tls-observatory/worker/mozillaEvaluationWorker"
	_ "github.com/mozilla/tls-observatory/worker/mozillaGradingWorker"
	_ "github.com/mozilla/tls-observatory/worker/ocspStatus"
	_ "github.com/mozilla/tls-observatory/worker/sslLabsClientSupport"
	_ "github.com/mozilla/tls-observatory/worker/symantecDistrust"
	_ "github.com/mozilla/tls-observatory/worker/top1m"
)
