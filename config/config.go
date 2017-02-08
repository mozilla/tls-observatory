package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/gcfg.v1"
)

type Config struct {
	General struct {
		Enable          bool
		Postgres        string
		PostgresDB      string
		PostgresUser    string
		PostgresPass    string
		PostgresUseTLS  bool
		CipherscanPath  string
		ScanRefreshRate int
		MaxProc         int
		Timeout         time.Duration
	}
	TrustStores struct {
		UbuntuTS    string
		MozillaTS   string
		MicrosoftTS string
		AppleTS     string
		AndroidTS   string
	}
}

func Load(path string) (conf Config, err error) {
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("configLoad() -> %v", e)
		}
	}()
	err = gcfg.ReadFileInto(&conf, path)
	if err != nil {
		panic(err)
	}
	if os.Getenv("TLSOBS_POSTGRES") != "" {
		conf.General.Postgres = os.Getenv("TLSOBS_POSTGRES")
	}
	if os.Getenv("TLSOBS_POSTGRESDB") != "" {
		conf.General.PostgresDB = os.Getenv("TLSOBS_POSTGRESDB")
	}
	if os.Getenv("TLSOBS_POSTGRESUSER") != "" {
		conf.General.PostgresUser = os.Getenv("TLSOBS_POSTGRESUSER")
	}
	if os.Getenv("TLSOBS_POSTGRESPASS") != "" {
		conf.General.PostgresPass = os.Getenv("TLSOBS_POSTGRESPASS")
	}
	return
}
