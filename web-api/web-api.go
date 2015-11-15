package main

import (
	"flag"
	"net/http"
	"os"

	_ "github.com/Sirupsen/logrus"

	"github.com/mozilla/TLS-Observer/config"
	"github.com/mozilla/TLS-Observer/logger"
	pg "github.com/mozilla/TLS-Observer/modules/postgresmodule"
)

func main() {

	log := logger.GetLogger()

	router := NewRouter()

	conf := config.ObserverConfig{}

	var cfgFile string
	var debug bool
	flag.StringVar(&cfgFile, "c", "/etc/observer/observer.cfg", "Input file csv format")
	flag.BoolVar(&debug, "debug", false, "Set debug logging")
	flag.Parse()

	log.Println(debug)

	if debug {
		logger.SetLevelToDebug()
	}

	_, err := os.Stat(cfgFile)
	if err != nil {
		log.Println(err)
		conf = config.GetObserverDefaults()
	} else {
		conf, err = config.ObserverConfigLoad(cfgFile)
		if err != nil {
			log.Println(err)
			conf = config.GetObserverDefaults()
		}
	}

	db, err := pg.RegisterConnection(conf.General.PostgresDB, conf.General.PostgresUser, conf.General.PostgresPass, conf.General.Postgres, "disable")

	if err != nil {
		log.Fatal(err)
	}

	// wait for clients
	err = http.ListenAndServe(":8083", Adapt(router, AddDB(db)))

	log.Fatal(err)
}
