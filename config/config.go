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
		APIListenAddr   string
		StaticAssetPath string
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
	if apiListenAddr := os.Getenv("TLSOBS_APILISTENADDR"); apiListenAddr != "" {
		conf.General.APIListenAddr = apiListenAddr
	}
	if cipherscanPath := os.Getenv("TLSOBS_CIPHERSCANPATH"); cipherscanPath != "" {
		conf.General.CipherscanPath = cipherscanPath
	}
	if ubuntuTSPath := os.Getenv("TLSOBS_UBUNTUTSPATH"); ubuntuTSPath != "" {
		conf.TrustStores.UbuntuTS = ubuntuTSPath
	}
	if mozillaTSPath := os.Getenv("TLSOBS_MOZILLATSPATH"); mozillaTSPath != "" {
		conf.TrustStores.MozillaTS = mozillaTSPath
	}
	if microsoftTSPath := os.Getenv("TLSOBS_MICROSOFTTSPATH"); microsoftTSPath != "" {
		conf.TrustStores.MicrosoftTS = microsoftTSPath
	}
	if appleTSPath := os.Getenv("TLSOBS_APPLETSPATH"); appleTSPath != "" {
		conf.TrustStores.AppleTS = appleTSPath
	}
	if androidTSPath := os.Getenv("TLSOBS_ANDROIDTSPATH"); androidTSPath != "" {
		conf.TrustStores.AndroidTS = androidTSPath
	}
	conf.General.StaticAssetPath = "./static/"
	if staticAssetPath := os.Getenv("TLSOBS_STATICASSETPATH"); staticAssetPath != "" {
		conf.General.StaticAssetPath = staticAssetPath
	}
	return
}
