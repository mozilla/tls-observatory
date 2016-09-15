package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/mozilla/tls-observatory/logger"
)

func httpError(w http.ResponseWriter, errorCode int, errorMessage string, args ...interface{}) {
	log := logger.GetLogger()
	log.Printf("%d: %s", errorCode, fmt.Sprintf(errorMessage, args...))
	http.Error(w, fmt.Sprintf(errorMessage, args...), errorCode)
	return
}

func Logger(inner http.Handler, name string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		inner.ServeHTTP(w, r)

		log.Printf(
			"%s\t%s\t%s\t%s",
			r.Method,
			r.RequestURI,
			name,
			time.Since(start),
		)
	})
}
