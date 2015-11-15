package logger

import (
	//	"os"

	log "github.com/Sirupsen/logrus"
	//	"github.com/Sirupsen/logrus/hooks/syslog"
)

var logger = log.New()

func init() {
}

func GetLogger() *log.Logger {
	return logger
}

func SetLevelToDebug() {
	logger.Level = log.DebugLevel
}

func SetLevelToInfo() {
	logger.Level = log.InfoLevel
}

func SetLevelToWarning() {
	logger.Level = log.WarnLevel
}
