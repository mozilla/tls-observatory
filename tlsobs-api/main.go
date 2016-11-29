package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/mozilla/tls-observatory/config"
	pg "github.com/mozilla/tls-observatory/database"
	"github.com/mozilla/tls-observatory/logger"
	"go.mozilla.org/mozlog"
)

func init() {
	// initialize the logger
	mozlog.Logger.LoggerName = "tlsobs-api"
	log.SetFlags(0)
}

func main() {

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
	dbtls := "disable"
	if conf.General.PostgresUseTLS {
		dbtls = "verify-full"
	}
	db, err := pg.RegisterConnection(
		conf.General.PostgresDB,
		conf.General.PostgresUser,
		conf.General.PostgresPass,
		conf.General.Postgres,
		dbtls)
	defer db.Close()
	if err != nil {
		log.Fatal(err)
	}
	db.SetMaxOpenConns(runtime.NumCPU() * 27)
	db.SetMaxIdleConns(2)
	// simple DB watchdog, crashes the process if connection dies
	go func() {
		for {
			var one uint
			err = db.QueryRow("SELECT 1").Scan(&one)
			if err != nil {
				log.Fatal("Database connection failed:", err)
			}
			if one != 1 {
				log.Fatal("Apparently the database doesn't know the meaning of one anymore. Crashing.")
			}
			time.Sleep(10 * time.Second)
		}
	}()

	scanRefreshRate = float64(conf.General.ScanRefreshRate)

	// wait for clients
	err = http.ListenAndServe(":8083",
		HandleMiddlewares(
			router,
			addRequestID(),
			addDB(db),
			logRequest(),
			setResponseHeaders(),
		),
	)

	log.Fatal(err)
}
