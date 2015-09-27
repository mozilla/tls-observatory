package main

import "net/http"

type Route struct {
	Name        string
	Method      string
	Pattern     string
	HandlerFunc http.HandlerFunc
}

type Routes []Route

var routes = Routes{
	Route{
		"Scan",
		"POST",
		"/api/v1/scan",
		ScanHandler,
	},
	Route{
		"Results",
		"GET",
		"/api/v1/results",
		ResultHandler,
	},
	Route{
		"Certificate",
		"GET",
		"/api/v1/certificate",
		CertificateHandler,
	},
}
