package mozlog // import "go.mozilla.org/mozlog"

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"time"
)

var Logger = &MozLogger{
	Output:     os.Stdout,
	LoggerName: "Application",
}

var hostname string

func Hostname() string {
	return hostname
}

// MozLogger implements the io.Writer interface
type MozLogger struct {
	Output     io.Writer
	LoggerName string
}

func init() {
	var err error
	hostname, err = os.Hostname()
	if err != nil {
		log.Printf("Can't resolve hostname: %v", err)
	}

	log.SetOutput(Logger)
	log.SetFlags(log.Lshortfile)
}

// Write converts the log to AppLog
func (m *MozLogger) Write(l []byte) (int, error) {
	log := NewAppLog(m.LoggerName, l)

	out, err := log.ToJSON()
	if err != nil {
		// Need someway to notify that this happened.
		fmt.Fprintln(os.Stderr, err)
		return 0, err
	}

	_, err = m.Output.Write(append(out, '\n'))
	return len(l), err
}

// AppLog implements Mozilla logging standard
type AppLog struct {
	Timestamp  int64
	Type       string
	Logger     string
	Hostname   string `json:",omitempty"`
	EnvVersion string
	Pid        int `json:",omitempty"`
	Severity   int `json:",omitempty"`
	Fields     map[string]interface{}
}

// NewAppLog returns a loggable struct
func NewAppLog(loggerName string, msg []byte) *AppLog {
	return &AppLog{
		Timestamp:  time.Now().UnixNano(),
		Type:       "app.log",
		Logger:     loggerName,
		Hostname:   hostname,
		EnvVersion: "2.0",
		Pid:        os.Getpid(),
		Fields: map[string]interface{}{
			"msg": string(bytes.TrimSpace(msg)),
		},
	}
}

// ToJSON converts a logline to JSON
func (a *AppLog) ToJSON() ([]byte, error) {
	return json.Marshal(a)
}
