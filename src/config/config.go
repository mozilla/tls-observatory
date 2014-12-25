package config

import (
	"fmt"

	"code.google.com/p/gcfg"
)

type ObserverConfig struct {
	General struct {
		RabbitMQRelay string
		ElasticSearch string
		MaxSimConns   int // Max simultaneous active retriever connections ( to avoid fd limit problems )
	}
	TrustStores struct {
		Name []string
		Path []string
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
	conf.TrustStores.Name = append(conf.TrustStores.Name, "")
	conf.TrustStores.Path = append(conf.TrustStores.Path, "")
	conf.General.ElasticSearch = "127.0.0.1:9200"
	conf.General.MaxSimConns = 50

	return conf
}
