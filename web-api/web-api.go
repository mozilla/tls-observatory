package main

import (
	"log"
	"net/http"
)

func main() {

	router := NewRouter()

	// wait for clients
	err := http.ListenAndServe(":8083", router)

	log.Fatal(err)
}
