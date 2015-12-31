/* This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

package main

import (
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/mozilla/tls-observatory/certificate"
	"github.com/mozilla/tls-observatory/database"
	"github.com/mozilla/tls-observatory/worker"
	_ "github.com/mozilla/tls-observatory/worker/mozillaEvaluationWorker"
)

func (r Run) AssertNotBefore(a Assertion, target string, cnb time.Time, notifchan chan Notification) {
	if a.Certificate.Validity.NotBefore == "" {
		return
	}
	nbmintime, nbmaxtime, err := parseValidity(a.Certificate.Validity.NotBefore)
	if err != nil {
		log.Printf("[error] failed to parse validity string %q: %v",
			a.Certificate.Validity.NotBefore, err)
		return
	}
	if cnb.Before(nbmintime) || cnb.After(nbmaxtime) {
		notifchan <- Notification{
			Target: target,
			Body: []byte(fmt.Sprintf(`Assertion certificate.validity.notBefore=%q failed because certificate starts on %q`,
				a.Certificate.Validity.NotBefore, cnb.String())),
			Conf: r.Notifications,
		}
	} else {
		debugprint("Assertion certificate.validity.notBefore=%q passed because certificate starts on %q",
			a.Certificate.Validity.NotBefore, cnb.String())
	}
	return
}

func (r Run) AssertNotAfter(a Assertion, target string, cna time.Time, notifchan chan Notification) {
	if a.Certificate.Validity.NotAfter == "" {
		return
	}
	nbmintime, nbmaxtime, err := parseValidity(a.Certificate.Validity.NotAfter)
	if err != nil {
		log.Printf("[error] failed to parse validity string %q: %v",
			a.Certificate.Validity.NotAfter, err)
		return
	}
	if cna.Before(nbmintime) || cna.After(nbmaxtime) {
		notifchan <- Notification{
			Target: target,
			Body: []byte(fmt.Sprintf(`Assertion certificate.validity.notAfter=%q failed because certificate expires on %q`,
				a.Certificate.Validity.NotAfter, cna.String())),
			Conf: r.Notifications,
		}
	} else {
		debugprint("Assertion certificate.validity.notAfter=%q passed because certificate expires on %q",
			a.Certificate.Validity.NotAfter, cna.String())
	}

	return
}

func parseValidity(validity string) (mintime, maxtime time.Time, err error) {
	var (
		isDays bool   = false
		n      uint64 = 0
	)
	suffix := validity[len(validity)-1]
	if suffix == 'd' {
		isDays = true
		suffix = 'h'
	}
	n, err = strconv.ParseUint(validity[1:len(validity)-1], 10, 64)
	if err != nil {
		return
	}
	if isDays {
		n = n * 24
	}
	duration := fmt.Sprintf("%d%c", n, suffix)
	d, err := time.ParseDuration(duration)
	switch validity[0] {
	case '>':
		mintime = time.Now().Add(d)
		maxtime = time.Date(9998, time.January, 11, 11, 11, 11, 11, time.UTC)
	case '<':
		// modification date is older than date
		mintime = time.Date(1111, time.January, 11, 11, 11, 11, 11, time.UTC)
		maxtime = time.Now().Add(d)
	}
	debugprint("Parsed validity time with mintime '%s' and maxtime '%s'\n",
		mintime.String(), maxtime.String())
	return
}

func (r Run) AssertAnalysis(a Assertion, results database.Scan, cert certificate.Certificate, notifchan chan Notification) {
	analyzer := a.Analysis.Analyzer
	if analyzer == "" {
		return
	}
	for _, ran := range results.AnalysisResults {
		if ran.Analyzer != analyzer {
			continue
		}
		if _, ok := worker.AvailableWorkers[analyzer]; !ok {
			log.Printf("[error] analyzer %q not found", analyzer)
			return
		}
		runner := worker.AvailableWorkers[analyzer].Runner
		pass, body, err := runner.(worker.HasAssertor).Assertor(ran.Result, []byte(a.Analysis.Result))
		if err != nil {
			log.Printf("[error] analyzer %q failed with error %v", analyzer, err)
			return
		}
		if !pass {
			notifchan <- Notification{
				Target: results.Target,
				Body:   body,
				Conf:   r.Notifications,
			}
		}
	}
}
