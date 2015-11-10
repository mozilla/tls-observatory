package main

import (
	"flag"
	"log"
	"net/http"
	"os"

	"github.com/mozilla/TLS-Observer/config"
	pg "github.com/mozilla/TLS-Observer/modules/postgresmodule"
)

func main() {

	router := NewRouter()

	conf := config.ObserverConfig{}

	var cfgFile string
	flag.StringVar(&cfgFile, "c", "/etc/observer/observer.cfg", "Input file csv format")
	flag.Parse()

	log.Println("Reading cfg")
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

	log.Println("Registering db")

	log.Println(conf)

	db, err := pg.RegisterConnection(conf.General.PostgresDB, conf.General.PostgresUser, conf.General.PostgresPass, conf.General.Postgres, "disable")

	if err != nil {
		log.Fatal(err)
	}

	log.Println("Listening")
	// wait for clients
	err = http.ListenAndServe(":8083", Adapt(router, AddDB(db)))

	log.Fatal(err)
}
