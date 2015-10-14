package main

import (
	"log"
	"net/http"

	"github.com/mozilla/TLS-Observer/config"
)

func main() {

	router := NewRouter()

	// wait for clients
	err := http.ListenAndServe(":8083", router)

	log.Fatal(err)
}
