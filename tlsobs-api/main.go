package main

import (
	"flag"
	"net/http"
	"os"
	"runtime"

	_ "github.com/Sirupsen/logrus"

	"github.com/mozilla/tls-observatory/config"
	pg "github.com/mozilla/tls-observatory/database"
	"github.com/mozilla/tls-observatory/logger"
)

func main() {

	log := logger.GetLogger()

	router := NewRouter()

	var cfgFile string
	var debug bool
	flag.StringVar(&cfgFile, "c", "/etc/tls-observatory/api.cfg", "Input file csv format")
	flag.BoolVar(&debug, "debug", false, "Set debug logging")
	flag.Parse()

	if debug {
		logger.SetLevelToDebug()
	}

	conf, err := config.Load(cfgFile)
	if err != nil {
		log.Fatal("Failed to load configuration: %v", err)
	}
	if !conf.General.Enable && os.Getenv("TLSOBS_API_ENABLE") != "on" {
		log.Fatal("API is disabled in configuration")
	}

	db, err := pg.RegisterConnection(conf.General.PostgresDB, conf.General.PostgresUser, conf.General.PostgresPass, conf.General.Postgres, "disable")
	defer db.Close()
	if err != nil {
		log.Fatal(err)
	}
	db.SetMaxOpenConns(runtime.NumCPU() * 10)
	db.SetMaxIdleConns(2)

	// wait for clients
	err = http.ListenAndServe(":8083", Adapt(router, AddDB(db)))

	log.Fatal(err)
}
