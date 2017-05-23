package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"testing"
)

// ensure environment variables override smtp & slack auth in config file
func TestConf(t *testing.T) {

	testconf := `
runs:
    - targets:
        - mozilla.org
        - jve.linuxwall.info
      assertions:
        - certificate:
                validity:
                    notafter: ">15d"
        - analysis:
            analyzer: mozillaEvaluationWorker
            result: '{"level": "modern"}'
      cron: "13 13 * * *"
      notifications:
        email:
            recipients:
                - testnotif@example.com
                - b64:dGVzdGI2NEBleGFtcGxlLm5ldAo=
        slack:
            channels:
                - 'somechannel'
smtp:
    host: localhost
    port: 25
    auth:
        user: someuser
        pass: somepass

slack:
    username: 'tls-observatory'
    iconemoji: ':telescope:'
    webhook: https://hooks.slack.com/services/not/a/realwebhook
`
	// override smtp user & pass using env variables
	err := os.Setenv("TLSOBS_RUNNER_SMTP_AUTH_USER", "secretuser")
	if err != nil {
		t.Fatal(err)
	}
	err = os.Setenv("TLSOBS_RUNNER_SMTP_AUTH_PASS", "secretpass")
	if err != nil {
		t.Fatal(err)
	}

	// override slack webhook using env variables
	err = os.Setenv("TLSOBS_RUNNER_SLACK_WEBHOOK", "secrethook")
	if err != nil {
		t.Fatal(err)
	}

	// write conf file to /tmp and read it back
	fd, err := ioutil.TempFile("", "tlsobsrunnertestconf")
	if err != nil {
		t.Fatal(err)
	}
	fi, err := fd.Stat()
	if err != nil {
		t.Fatal(err)
	}
	filename := fmt.Sprintf("%s/%s", os.TempDir(), fi.Name())
	_, err = fd.Write([]byte(testconf))
	if err != nil {
		t.Fatal(err)
	}
	fd.Close()
	conf := getConf(filename)

	// test the conf
	if len(conf.Runs) != 1 {
		t.Fatalf("invalid number of runs in configuration, expected 1, got %d", len(conf.Runs))
	}
	if conf.Runs[0].Targets[0] != "mozilla.org" || conf.Runs[0].Targets[1] != "jve.linuxwall.info" {
		t.Fatalf("invalid targets, expected 'mozilla.org' and 'jve.linuxwall.info', got %+v",
			conf.Runs[0].Targets)
	}
	if len(conf.Runs[0].Assertions) != 2 {
		t.Fatalf("invalid assertions, expected 2, got %d", len(conf.Runs[0].Assertions))
	}
	if conf.Runs[0].Assertions[0].Certificate.Validity.NotAfter != ">15d" {
		t.Fatalf("invalid certificate assertion, expected 'notafter=\">15d\"', got %q",
			conf.Runs[0].Assertions[0].Certificate.Validity.NotAfter)
	}
	if conf.Runs[0].Assertions[1].Analysis.Analyzer != "mozillaEvaluationWorker" ||
		conf.Runs[0].Assertions[1].Analysis.Result != `{"level": "modern"}` {
		t.Fatalf("invalid analyzer assertion, expected mozillaEvaluationWorker with result `'{\"level\": \"modern\"}'`, got %q with result %q",
			conf.Runs[0].Assertions[1].Analysis.Analyzer, conf.Runs[0].Assertions[1].Analysis.Result)
	}
	if conf.Runs[0].Cron != "13 13 * * *" {
		t.Fatalf("invalid cron, expected '13 13 * * *', got %q", conf.Runs[0].Cron)
	}
	if len(conf.Runs[0].Notifications.Email.Recipients) != 2 {
		t.Fatalf("invalid email recipients, expected 2, got %d",
			len(conf.Runs[0].Notifications.Email.Recipients))
	}
	if conf.Runs[0].Notifications.Email.Recipients[0] != "testnotif@example.com" ||
		conf.Runs[0].Notifications.Email.Recipients[1] != "testb64@example.net" {
		t.Fatalf("invalid recipients, expected 'testnotif@example.com' and 'testb64@example.net', got %+v",
			conf.Runs[0].Notifications.Email.Recipients)
	}
	if conf.Smtp.Host != "localhost" {
		t.Fatalf("invalid smtp host, expected 'localhost, got %q", conf.Smtp.Host)
	}
	if conf.Smtp.Port != 25 {
		t.Fatalf("invalid smtp port, expected 25, got %d", conf.Smtp.Port)
	}
	if conf.Smtp.Auth.User != "secretuser" {
		t.Fatalf("invalid smtp auth user, expected 'secretuser', got %q", conf.Smtp.Auth.User)
	}
	if conf.Smtp.Auth.Pass != "secretpass" {
		t.Fatalf("invalid smtp auth pass, expected 'secretpass', got %q", conf.Smtp.Auth.Pass)
	}
	if conf.Runs[0].Notifications.Slack.Channels[0] != "somechannel" {
		t.Fatalf("invalid slack channel, expected 'somechannel', got %q",
			conf.Runs[0].Notifications.Slack.Channels[0])
	}
	if conf.Slack.Username != "tls-observatory" {
		t.Fatalf("invalid slack username, expected 'tls-observatory', got %q", conf.Slack.Username)
	}
	if conf.Slack.IconEmoji != ":telescope:" {
		t.Fatalf("invalid slack icon, expected ':telescope:', got %q", conf.Slack.IconEmoji)
	}
	if conf.Slack.Webhook != "secrethook" {
		t.Fatalf("invalid slack webhook, expected 'secrethook', got %q", conf.Slack.Webhook)
	}
}
