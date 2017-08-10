package main

import (
	"context"
	"log"
	"net/http"

	pg "github.com/mozilla/tls-observatory/database"
)

// Middleware wraps an http.Handler with additional
// functionality.
type Middleware func(http.Handler) http.Handler

const (
	ctxDBKey = "db"
	ctxReqID = "reqID"
)

func logRequest() Middleware {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h.ServeHTTP(w, r)
			rid := "-"
			val := r.Context().Value(ctxReqID)
			if val != nil {
				rid = val.(string)
			}
			log.Printf("x-forwarded-for=[%s] %s %s %s user-agent=%s req-id=%s",
				r.Header.Get("X-Forwarded-For"), r.Method, r.Proto, r.URL.String(), r.UserAgent(), rid)
		})
	}
}

func addDB(db *pg.DB) Middleware {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h.ServeHTTP(w, addtoContext(r, ctxDBKey, db))
		})
	}
}

func setResponseHeaders() Middleware {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS, POST")
			w.Header().Set("Access-Control-Max-Age", "86400")
			w.Header().Add("Content-Security-Policy", "default-src 'self'; child-src 'self';")
			w.Header().Add("X-Frame-Options", "SAMEORIGIN")
			w.Header().Add("X-Content-Type-Options", "nosniff")
			w.Header().Add("Strict-Transport-Security", "max-age=31536000;")
			w.Header().Add("Public-Key-Pins", `max-age=5184000; pin-sha256="WoiWRyIOVNa9ihaBciRSC7XHjliYS9VwUGOIud4PB18="; pin-sha256="r/mIkG3eEpVdm+u/ko/cwxzOMo1bk4TyHIlByibiA5E="; pin-sha256="YLh1dUR9y6Kja30RrAn7JKnbQG/uEtLMkBgFF2Fuihg="; pin-sha256="sRHdihwgkaib1P1gxX8HFszlD+7/gTfNvuAybgLPNis=";`)
			h.ServeHTTP(w, r)
		})
	}
}

func addRequestID() Middleware {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rid := newRequestID()
			h.ServeHTTP(w, addtoContext(r, ctxReqID, rid))
		})
	}
}

//  Run the request through all middlewares
func HandleMiddlewares(h http.Handler, adapters ...Middleware) http.Handler {
	// To make the middleware run in the order in which they are specified,
	// we reverse through them in the Middleware function, rather than just
	// ranging over them
	for i := len(adapters) - 1; i >= 0; i-- {
		h = adapters[i](h)
	}
	return h
}

// addToContext add the given key value pair to the given request's context
func addtoContext(r *http.Request, key string, value interface{}) *http.Request {
	ctx := r.Context()
	return r.WithContext(context.WithValue(ctx, key, value))
}
