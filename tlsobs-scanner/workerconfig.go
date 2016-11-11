package main

import (
	//import mozillaEvaluationWorker to make it available for compliance evaluation
	_ "github.com/mozilla/tls-observatory/worker/evCheckerWorker"
	_ "github.com/mozilla/tls-observatory/worker/mozillaEvaluationWorker"
	_ "github.com/mozilla/tls-observatory/worker/mozillaGradingWorker"
)
