package main

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/mozilla/tls-observatory/config"
)

func NewRouter(conf config.Config) *mux.Router {
	router := mux.NewRouter().StrictSlash(true)
	router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(
		http.Dir(conf.General.StaticAssetPath))))
	for _, route := range routes {
		var handler http.Handler

		handler = route.HandlerFunc

		router.
			Methods(route.Method).
			Path(route.Pattern).
			Name(route.Name).
			Handler(handler)

	}

	return router
}

type Route struct {
	Name        string
	Method      string
	Pattern     string
	HandlerFunc http.HandlerFunc
}

type Routes []Route

var routes = Routes{
	Route{
		"Index",
		"GET",
		"/",
		IndexHandler,
	},
	Route{
		"Heartbeat",
		"GET",
		"/__heartbeat__",
		heartbeatHandler,
	},
	Route{
		"LbHeartbeat",
		"GET",
		"/__lbheartbeat__",
		lbHeartbeatHandler,
	},
	Route{
		"Version",
		"GET",
		"/__version__",
		versionHandler,
	},
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
	Route{
		"Certificate",
		"POST",
		"/api/v1/certificate",
		PostCertificateHandler,
	},
	Route{
		"Paths",
		"GET",
		"/api/v1/paths",
		PathsHandler,
	},
	Route{
		"Truststore",
		"GET",
		"/api/v1/truststore",
		TruststoreHandler,
	},
	Route{
		"IssuerEECount",
		"GET",
		"/api/v1/issuereecount",
		IssuerEECountHandler,
	},
	// CORS preflight endpoints
	Route{
		"CORS Preflight",
		"OPTIONS",
		"/api/v1/scan",
		PreflightHandler,
	},
	Route{
		"CORS Preflight",
		"OPTIONS",
		"/api/v1/results",
		PreflightHandler,
	},
	Route{
		"CORS Preflight",
		"OPTIONS",
		"/api/v1/certificate",
		PreflightHandler,
	},
	Route{
		"CORS Preflight",
		"OPTIONS",
		"/api/v1/paths",
		PreflightHandler,
	},
	Route{
		"CORS Preflight",
		"OPTIONS",
		"/api/v1/truststore",
		PreflightHandler,
	},
	Route{
		"CORS Preflight",
		"OPTIONS",
		"/api/v1/issuereecount",
		PreflightHandler,
	},
	Route{
		"Heartbeat",
		"GET",
		"/api/v1/__heartbeat__",
		HeartbeatHandler,
	},
	Route{
		"Statistics",
		"GET",
		"/api/v1/__stats__",
		StatsHandler,
	},
}
