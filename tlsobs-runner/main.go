/* This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/gorhill/cronexpr"
	"github.com/mozilla/tls-observatory/certificate"
	"github.com/mozilla/tls-observatory/database"

	"gopkg.in/yaml.v2"
)

type Configuration struct {
	Runs []Run
	Smtp struct {
		Host string
		Port int
		From string
		Auth struct {
			User, Pass string
		}
	}
	Slack struct {
		Username, IconEmoji, Webhook string
	}
}

type Run struct {
	Targets       []string
	Assertions    []Assertion
	Cron          string
	Notifications NotificationsConf
}

type Assertion struct {
	Certificate struct {
		Validity struct {
			NotBefore string
			NotAfter  string
		}
	}
	Analysis struct {
		Analyzer string
		Result   string `json:"result"`
	}
}

type NotificationsConf struct {
	Irc struct {
		Channels []string
	}
	Email struct {
		Recipients []string
	}
	Slack struct {
		Channels []string
	}
}

var (
	cfgFile     string
	observatory string
	debug       bool
	conf        Configuration
)

func main() {
	flag.StringVar(&observatory, "observatory", "https://tls-observatory.services.mozilla.com", "URL of the observatory")
	flag.StringVar(&cfgFile, "c", "/etc/tls-observatory/runner.yaml", "YAML configuration file")
	flag.BoolVar(&debug, "debug", false, "Set debug logging")
	flag.Parse()
	conf = getConf(cfgFile)
	exit := make(chan bool)
	for i, run := range conf.Runs {
		go run.start(i)
	}
	<-exit
}

func (r Run) start(id int) {
	for {
		cexpr, err := cronexpr.Parse(r.Cron)
		if err != nil {
			log.Printf("Failed to parse cron expression %q: %v", r.Cron, err)
			time.Sleep(time.Minute)
			continue
		}
		// sleep until the next run is scheduled to happen
		nrun := cexpr.Next(time.Now())
		waitduration := nrun.Sub(time.Now())
		log.Printf("[info] run %d will start at %v (in %v)", id, nrun, waitduration)
		time.Sleep(waitduration)

		notifchan := make(chan Notification)
		done := make(chan bool)
		go processNotifications(notifchan, done)
		var wg sync.WaitGroup
		for _, target := range r.Targets {
			log.Printf("[info] run %d starting scan of target %q", id, target)
			id, err := r.scan(target)
			debugprint("got scan id %d", id)
			if err != nil {
				log.Printf("[error] failed to launch against %q: %v", target, err)
				continue
			}
			wg.Add(1)
			go r.evaluate(id, notifchan, &wg)
		}
		wg.Wait()
		close(notifchan)
		<-done
	}
}

type scan struct {
	ID int64 `json:"scan_id"`
}

func (r Run) scan(target string) (id int64, err error) {
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("scan(target=%q) -> %v", target, e)
		}
	}()
	resp, err := http.Post(observatory+"/api/v1/scan?rescan=true&target="+target, "application/json", nil)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	if resp.StatusCode != http.StatusOK {
		panic(fmt.Sprintf("Scan failed. HTTP %d: %s", resp.StatusCode, body))
	}
	var s scan
	err = json.Unmarshal(body, &s)
	if err != nil {
		panic(err)
	}
	if s.ID < 1 {
		panic("failed to launch scan on target " + target)
	}
	id = s.ID
	return
}

func (r Run) evaluate(id int64, notifchan chan Notification, wg *sync.WaitGroup) {
	defer func() {
		if e := recover(); e != nil {
			log.Printf("[error] evaluate(id=%q) -> %v", id, e)
		}
		wg.Done()
	}()
	var (
		results database.Scan
		cert    certificate.Certificate
		err     error
	)
	for {
		resp, err := http.Get(fmt.Sprintf("%s/api/v1/results?id=%d", observatory, id))
		if err != nil {
			panic(err)
		}
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			panic(err)
		}
		err = json.Unmarshal(body, &results)
		if err != nil {
			panic(err)
		}
		if results.Complperc >= 100 {
			debugprint("scan id %d completed", id)
			break
		}
		time.Sleep(5 * time.Second)
	}
	debugprint("getting certificate id %d", results.Cert_id)
	if !results.Has_tls && results.Cert_id < 1 {
		log.Printf("[info] target %q is not TLS enabled", results.Target)
		return
	}
	cert, err = getCert(results.Cert_id)
	if err != nil {
		panic(err)
	}
	for _, a := range r.Assertions {
		r.AssertNotBefore(a, results.Target, cert.Validity.NotBefore, notifchan)
		r.AssertNotAfter(a, results.Target, cert.Validity.NotAfter, notifchan)
		r.AssertAnalysis(a, results, cert, notifchan)
	}
	return
}

func getCert(id int64) (cert certificate.Certificate, err error) {
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("getCert(id=%q) -> %v", id, e)
		}
	}()
	resp, err := http.Get(fmt.Sprintf("%s/api/v1/certificate?id=%d", observatory, id))
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	err = json.Unmarshal(body, &cert)
	if err != nil {
		panic(err)
	}
	return
}

func debugprint(format string, a ...interface{}) {
	if debug {
		log.Printf("[debug] "+format, a...)
	}
}

// getConf first read the configuration from a local YAML file then overrides it
// with the content of the TLSOBS_RUNNER_CONF var (which much contain a full yaml file
// encoded in base64), and then overrides the SMTP settings with various SMTP env var
func getConf(cfg string) (c Configuration) {
	// load the local configuration file
	fd, err := ioutil.ReadFile(cfg)
	if err != nil {
		log.Fatal(err)
	}
	err = yaml.Unmarshal(fd, &c)
	if err != nil {
		log.Fatalf("error: %v", err)
	}
	// iterate over notifications in targets and unbase64 the values
	for i, run := range c.Runs {
		for j, rcpt := range run.Notifications.Email.Recipients {
			if len(rcpt) < 5 || rcpt[0:4] != "b64:" {
				continue
			}
			data, err := base64.StdEncoding.DecodeString(rcpt[4:])
			if err != nil {
				log.Fatalf("error while decoding b64 recipient: %v", err)
			}
			c.Runs[i].Notifications.Email.Recipients[j] = fmt.Sprintf("%s", bytes.TrimRight(data, "\n"))
		}
	}
	if os.Getenv("TLSOBS_RUNNER_SMTP_HOST") != "" {
		c.Smtp.Host = os.Getenv("TLSOBS_RUNNER_SMTP_HOST")
	}
	if os.Getenv("TLSOBS_RUNNER_SMTP_PORT") != "" {
		var err error
		c.Smtp.Port, err = strconv.Atoi(os.Getenv("TLSOBS_RUNNER_SMTP_PORT"))
		if err != nil {
			log.Printf("[error] failed to read smtp port from env variable: %v", err)
		}
	}
	if os.Getenv("TLSOBS_RUNNER_SMTP_FROM") != "" {
		c.Smtp.From = os.Getenv("TLSOBS_RUNNER_SMTP_FROM")
	}
	if os.Getenv("TLSOBS_RUNNER_SMTP_AUTH_USER") != "" {
		c.Smtp.Auth.User = os.Getenv("TLSOBS_RUNNER_SMTP_AUTH_USER")
	}
	if os.Getenv("TLSOBS_RUNNER_SMTP_AUTH_PASS") != "" {
		c.Smtp.Auth.Pass = os.Getenv("TLSOBS_RUNNER_SMTP_AUTH_PASS")
	}
	if os.Getenv("TLSOBS_RUNNER_SLACK_USERNAME") != "" {
		c.Slack.Username = os.Getenv("TLSOBS_RUNNER_USERNAME")
	}
	if os.Getenv("TLSOBS_RUNNER_SLACK_ICONEMOJI") != "" {
		c.Slack.IconEmoji = os.Getenv("TLSOBS_RUNNER_SLACK_ICONEMOJI")
	}
	if os.Getenv("TLSOBS_RUNNER_SLACK_WEBHOOK") != "" {
		c.Slack.Webhook = os.Getenv("TLSOBS_RUNNER_SLACK_WEBHOOK")
	}
	return c
}
