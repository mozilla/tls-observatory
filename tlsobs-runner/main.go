/* This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
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
		Relay string
		From  string
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

	// load the local configuration file
	fd, err := ioutil.ReadFile(cfgFile)
	if err != nil {
		log.Fatal(err)
	}
	err = yaml.Unmarshal(fd, &conf)
	if err != nil {
		log.Fatalf("error: %v", err)
	}
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
			panic(err)
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
			debugprint("scanning target %s", target)
			id, err := r.scan(target)
			debugprint("got scan id %s", id)
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
	ID string `json:"scan_id"`
}

func (r Run) scan(target string) (id string, err error) {
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("scan(target=%q) -> %v", e)
		}
	}()
	resp, err := http.Post(observatory+"/api/v1/scan?target="+target, "application/json", nil)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	var s scan
	err = json.Unmarshal(body, &s)
	if err != nil {
		panic(err)
	}
	if s.ID == "" {
		panic("failed to launch scan on target " + target)
	}
	id = s.ID
	return
}

func (r Run) evaluate(id string, notifchan chan Notification, wg *sync.WaitGroup) {
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
		resp, err := http.Get(observatory + "/api/v1/results?id=" + id)
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
			debugprint("scan id %s completed", id)
			break
		}
		time.Sleep(1 * time.Second)
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
			err = fmt.Errorf("getCert(id=%q) -> %v", e)
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
