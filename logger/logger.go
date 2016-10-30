package logger

import log "github.com/Sirupsen/logrus"

var logger = init_logger()

func init_logger() *log.Logger {

	l := log.New()

	f := &log.TextFormatter{}

	f.DisableColors = true

	l.Level = log.InfoLevel
	l.Formatter = f

	/*
		//add syslog.LOG_DEBUG as the lowest level of logging to syslog ( so no filtering is applied.
		//All the log filtering is taken care on the local logger level
		hook, err := logrus_syslog.NewSyslogHook("", "", syslog.LOG_DEBUG, "")

		if err == nil {
			l.Hooks.Add(hook)
		} else {
			l.WithFields(log.Fields{
				"error": err.Error(),
			}).Error("Could not add syslog logging hook")
		}
	*/
	return l

}

//GetLogger returns the global pre-initialised logger pointer
func GetLogger() *log.Logger {
	return logger
}

//SetLevelToDebug set the minimun enabled log level to Debug
func SetLevelToDebug() {
	logger.Level = log.DebugLevel
}

//SetLevelToInfo set the minimun enabled log level to Info
func SetLevelToInfo() {
	logger.Level = log.InfoLevel
}

//SetLevelToWarning set the minimun enabled log level to Warning
func SetLevelToWarning() {
	logger.Level = log.WarnLevel
}
