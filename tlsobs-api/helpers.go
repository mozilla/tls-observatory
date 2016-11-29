package main

import (
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"time"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

func newRequestID() string {
	var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	b := make([]rune, 8)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func httpError(w http.ResponseWriter, r *http.Request, errorCode int, errorMessage string, args ...interface{}) {
	rid := "-"
	val := r.Context().Value(ctxReqID)
	if val != nil {
		rid = val.(string)
	}
	log.Printf("req-id=%s error-code=%d msg=%s", rid, errorCode, fmt.Sprintf(errorMessage, args...))
	http.Error(w, fmt.Sprintf(errorMessage, args...), errorCode)
	return
}
