package main

import (
	"fmt"
	"log"
	"net/http"
	"time"
)

func httpError(w http.ResponseWriter, errorCode int, errorMessage string, args ...interface{}) {
	log.Printf("%d: %s", errorCode, fmt.Sprintf(errorMessage, args...))
	http.Error(w, fmt.Sprintf(errorMessage, args...), errorCode)
	return
}

func logRequest(r *http.Request, code, size int) {
	log.Printf("x-forwarded-for=[%s] %s %s %s resp_code=%d resp_size=%d user-agent=%s",
		r.Header.Get("X-Forwarded-For"), r.Method, r.Proto, r.URL.String(),
		code, size, r.UserAgent())
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
