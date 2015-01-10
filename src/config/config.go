package config

import (
	"fmt"

	"code.google.com/p/gcfg"
)

type RetrieverConfig struct {
	General struct {
		RabbitMQRelay string
		MaxSimConns   int // Max simultaneous active retriever connections ( to avoid fd limit problems )
	}
}

type AnalyzerConfig struct {
	General struct {
		RabbitMQRelay string
		ElasticSearch string
	}
	TrustStores struct {
		Name []string
		Path []string
	}
}

func RetrieverConfigLoad(path string) (conf RetrieverConfig, err error) {
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("configLoad() -> %v", e)
		}
	}()
	var c RetrieverConfig
	err = gcfg.ReadFileInto(&c, path)

	return c, err
}

func AnalyzerConfigLoad(path string) (conf AnalyzerConfig, err error) {
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("configLoad() -> %v", e)
		}
	}()
	var c AnalyzerConfig
	err = gcfg.ReadFileInto(&c, path)

	return c, err
}

func GetRetrieverDefaults() RetrieverConfig {
	conf := RetrieverConfig{}

	conf.General.RabbitMQRelay = "amqp://guest:guest@localhost:5672/"
	conf.General.MaxSimConns = 50

	return conf
}

func GetAnalyzerDefaults() AnalyzerConfig {
	conf := AnalyzerConfig{}

	conf.General.RabbitMQRelay = "amqp://guest:guest@localhost:5672/"
	conf.TrustStores.Name = append(conf.TrustStores.Name, "")
	conf.TrustStores.Path = append(conf.TrustStores.Path, "")
	conf.General.ElasticSearch = "127.0.0.1:9200"

	return conf
}
