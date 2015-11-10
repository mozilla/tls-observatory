package main

import (
	"log"
	"net/http"

	"github.com/gorilla/context"

	pg "github.com/mozilla/TLS-Observer/modules/postgresmodule"
)

// Adapter wraps an http.Handler with additional
// functionality.
type Adapter func(http.Handler) http.Handler

const dbKey = "db"

func Logging(l *log.Logger) Adapter {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			l.Println(r.Method, r.URL.Path)
			h.ServeHTTP(w, r)
		})
	}
}

func AddDB(db *pg.DB) Adapter {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			context.Set(r, dbKey, db)
			h.ServeHTTP(w, r)
			context.Clear(r)
		})
	}
}

// Adapt h with all specified adapters.
func Adapt(h http.Handler, adapters ...Adapter) http.Handler {
	for _, adapter := range adapters {
		h = adapter(h)
	}
	return h
}
