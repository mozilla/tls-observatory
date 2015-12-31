/* This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

package main

import (
	"fmt"
	"log"
	"net/smtp"
	"time"
)

type Notification struct {
	Target string            `json:"target"`
	Body   []byte            `json:"body"`
	Conf   NotificationsConf `json:"-"`
}

func processNotifications(notifchan chan Notification, done chan bool) {
	emailntfs := make(map[string][]byte)
	ircntfs := make(map[string][]byte)
	for n := range notifchan {
		log.Printf("[info] received notification for target %s with body: %s", n.Target, n.Body)
		for _, rcpt := range n.Conf.Email.Recipients {
			var body []byte
			if _, ok := emailntfs[rcpt]; ok {
				body = emailntfs[rcpt]
			}
			emailntfs[rcpt] = []byte(fmt.Sprintf("%s\n%s: %s", body, n.Target, n.Body))
		}
		for _, rcpt := range n.Conf.Irc.Channels {
			var body []byte
			if _, ok := ircntfs[rcpt]; ok {
				body = ircntfs[rcpt]
			}
			ircntfs[rcpt] = []byte(fmt.Sprintf("%s\n%s: %s", body, n.Target, n.Body))
		}
	}
	for rcpt, body := range emailntfs {
		sendMail(rcpt, body)
	}
	done <- true
}

func sendMail(rcpt string, body []byte) (err error) {
	var auth smtp.Auth
	if conf.Smtp.Auth.User != "" && conf.Smtp.Auth.Pass != "" {
		auth = smtp.PlainAuth("", conf.Smtp.Auth.User, conf.Smtp.Auth.Pass, conf.Smtp.Host)
		debugprint("SMTP authenticated as %q", conf.Smtp.Auth.User)
	}
	debugprint("Publishing notification to %q from %q on server %s:%d",
		rcpt, conf.Smtp.From, conf.Smtp.Host, conf.Smtp.Port)
	err = smtp.SendMail(
		fmt.Sprintf("%s:%d", conf.Smtp.Host, conf.Smtp.Port),
		auth,
		conf.Smtp.From,
		[]string{rcpt},
		[]byte(fmt.Sprintf(`From: %s
To: %s
Subject: TLS Observatory runner results
Date: %s

%s`, conf.Smtp.From, rcpt, time.Now().Format("Mon, 2 Jan 2006 15:04:05 -0700"), body)),
	)
	return
}
