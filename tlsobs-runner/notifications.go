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
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("sendMail-> %v", e)
		}
	}()
	// Connect to the remote SMTP server.
	c, err := smtp.Dial(conf.Smtp.Relay)
	if err != nil {
		panic(err)
	}

	// Set the sender and recipient first
	err = c.Mail(conf.Smtp.From)
	if err != nil {
		panic(err)
	}
	err = c.Rcpt(rcpt)
	if err != nil {
		panic(err)
	}
	// Send the email body.
	wc, err := c.Data()
	if err != nil {
		panic(err)
	}
	_, err = fmt.Fprintf(wc, `From: %s
To: %s
Subject: TLS Observatory runner results
Date: %s

%s
`, conf.Smtp.From, rcpt, time.Now().Format("Mon, 2 Jan 2006 15:04:05 -0700"), body)
	if err != nil {
		panic(err)
	}
	err = wc.Close()
	if err != nil {
		panic(err)
	}

	// Send the QUIT command and close the connection.
	err = c.Quit()
	if err != nil {
		panic(err)
	}
	return
}
