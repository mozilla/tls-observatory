package config

import (
	"fmt"

	"code.google.com/p/gcfg"
)

type ObserverConfig struct {
	General struct {
		RabbitMQRelay string
		ElasticSearch string
	}
	TrustStores struct {
		TrustStoreName []string
		TrustStorePath []string
	}
}

func ConfigLoad(path string) (conf ObserverConfig, err error) {
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("configLoad() -> %v", e)
		}
	}()
	var c ObserverConfig
	err = gcfg.ReadFileInto(&c, path)

	return c, err
}

func GetDefaults() ObserverConfig {
	conf := ObserverConfig{}

	conf.General.RabbitMQRelay = "amqp://guest:guest@localhost:5672/"
	conf.TrustStores.TrustStoreName = append(conf.TrustStores.TrustStoreName, "")
	conf.TrustStores.TrustStorePath = append(conf.TrustStores.TrustStorePath, "")
	conf.General.ElasticSearch = "127.0.0.1:9200"

	return conf
}
