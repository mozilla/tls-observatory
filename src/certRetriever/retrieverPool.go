package main

import (
	// stdlib packages
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"runtime"
	"strings"
	"time"

	// custom packages
	"config"
	"modules/amqpmodule"

	// 3rd party dependencies
)

const rxQueue = "scan_ready_queue"
const txQueue = "scan_results_queue"

var workerCount int

func failOnError(err error, msg string) {
	if err != nil {
		log.Fatalf("%s: %s", msg, err)
		panic(fmt.Sprintf("%s: %s", msg, err))
	}
}

func panicIf(err error) {
	if err != nil {
		log.Println(fmt.Sprintf("%s", err))
	}
}

type CertChain struct {
	Domain string   `json:"domain"`
	IP     string   `json:"ip"`
	Certs  []string `json:"certs"`
}

func worker(msg []byte) {
	defer func() {
		workerCount--
	}()

	certs, ip, err := retrieveCertFromHost(string(msg), "443", true)
	panicIf(err)
	if certs == nil {
		log.Println("no certificate retrieved from", string(msg))
		return
	}

	var chain = CertChain{}

	chain.Domain = string(msg)

	chain.IP = ip

	for _, cert := range certs {

		chain.Certs = append(chain.Certs, base64.StdEncoding.EncodeToString(cert.Raw))

	}

	jsonChain, er := json.MarshalIndent(chain, "", "    ")
	panicIf(er)

	amqpmodule.Publish(txQueue, []byte(jsonChain))
}

func retrieveCertFromHost(domainName, port string, skipVerify bool) ([]*x509.Certificate, string, error) {

	config := tls.Config{InsecureSkipVerify: skipVerify}

	canonicalName := domainName + ":" + port

	ip := ""

	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", canonicalName, &config)

	if err != nil {
		return nil, ip, err
	}
	defer conn.Close()

	ip = strings.TrimSuffix(conn.RemoteAddr().String(), ":443")

	certs := conn.ConnectionState().PeerCertificates

	if certs == nil {
		return nil, ip, errors.New("Could not get server's certificate from the TLS connection.")
	}

	return certs, ip, nil
}

func printIntro() {
	fmt.Println(`
	##################################
	#         CertRetriever          #
	##################################
	`)
}

var sem chan bool

func main() {
	var (
		err error
	)
	cores := runtime.NumCPU()
	runtime.GOMAXPROCS(cores * 2)

	printIntro()

	conf := config.RetrieverConfig{}

	var cfgFile string
	flag.StringVar(&cfgFile, "c", "/etc/observer/retriever.cfg", "Input file csv format")
	flag.Parse()

	_, err = os.Stat(cfgFile)
	failOnError(err, "Missing configuration file from '-c' or /etc/observer/retriever.cfg")

	conf, err = config.RetrieverConfigLoad(cfgFile)
	if err != nil {
		conf = config.GetRetrieverDefaults()
	}

	err = amqpmodule.RegisterURL(conf.General.RabbitMQRelay)

	failOnError(err, "Failed to register RabbitMQ")

	msgs, err := amqpmodule.Consume(rxQueue)

	for d := range msgs {
		// block until a worker is available
		for {
			if workerCount < conf.General.MaxSimConns {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		workerCount++
		go worker(d)
		log.Printf("Domain %s sent to worker. %d workers currently active.", d, workerCount)
	}
}
