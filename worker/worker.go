package worker

import (
	"fmt"
	"os"
)

type WorkerResult struct {
	Success bool     `json:"success"`
	Result  []byte   `json:"elements"` //JSON encoded
	Errors  []string `json:"errors"`
}

type WorkerInfo struct {
	Runner      Worker
	Description string
}

var AvailableWorkers = make(map[string]WorkerInfo)

func RegisterWorker(name string, info WorkerInfo) {
	if _, exist := AvailableWorkers[name]; exist {
		fmt.Fprintf(os.Stderr, "RegisterModule: a module named '%s' has already been registered.\nAre you trying to import the same module twice?\n", name)
		os.Exit(1)
	}
	AvailableModules[name] = info
}

type Worker interface {
	Run([]byte, chan ModuleResult)
}
