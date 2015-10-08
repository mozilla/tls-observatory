package config

import (
	"code.google.com/p/gcfg"
	"fmt"
	"github.com/jvehent/gozdef"
)

type ObserverConfig struct {
	General struct {
		RabbitMQRelay  string
		Postgres       string
		CipherscanPath string
		GoRoutines     int // * cores = The Max number of spawned Goroutines
	}
	TrustStores struct {
		Name []string
		Path []string
	}
	MozDef gozdef.MqConf
}

func ObserverConfigLoad(path string) (conf ObserverConfig, err error) {
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("configLoad() -> %v", e)
		}
	}()
	var c ObserverConfig
	err = gcfg.ReadFileInto(&c, path)

	return c, err
}

func GetObserverDefaults() ObserverConfig {
	conf := ObserverConfig{}

	conf.General.RabbitMQRelay = "amqp://guest:guest@localhost:5672/"
	conf.TrustStores.Name = append(conf.TrustStores.Name, "")
	conf.TrustStores.Path = append(conf.TrustStores.Path, "")
	conf.General.Postgres = "127.0.0.1:5432"
	conf.General.CipherscanPath = "../../../cipherscan/cipherscan"
	conf.General.GoRoutines = 10

	return conf
}
