package main

import (
	// stdlib packages

	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"strconv"
	"sync"

	// custom packages
	"config"
	"modules/amqpmodule"
	es "modules/elasticsearchmodule"
)

const rxQueue = "conn_scan_results_queue"
const esIndex = "observer"
const esType = "connection"

var broker *amqpmodule.Broker

//the 2 following structs represent the cipherscan output.

type ScanInfo struct {
	Target       string        `json:"target"`
	Timestamp    string        `json:"utctimestamp"`
	ServerSide   string        `json:"serverside"`
	CipherSuites []Ciphersuite `json:"ciphersuite"`
}

type Ciphersuite struct {
	Cipher       string   `json:"cipher"`
	Protocols    []string `json:"protocols"`
	PubKey       []string `json:"pubkey"`
	SigAlg       []string `json:"sigalg"`
	Trusted      string   `json:"trusted"`
	TicketHint   string   `json:"ticket_hint"`
	OCSPStapling string   `json:"ocsp_stapling"`
	PFS          string   `json:"pfs"`
}

//the following structs represent the output we want to provide to DB.

type ConnectionInfo struct {
	ConnectionTimestamp string                  `json:"connectionTimestamp"`
	ServerSide          bool                    `json:"serverside"`
	CipherSuites        []ConnectionCiphersuite `json:"ciphersuite"`
}

type ConnectionCiphersuite struct {
	Cipher       string   `json:"cipher"`
	Protocols    []string `json:"protocols"`
	PubKey       float64  `json:"pubkey"`
	SigAlg       string   `json:"sigalg"`
	TicketHint   string   `json:"ticket_hint"`
	OCSPStapling bool     `json:"ocsp_stapling"`
	PFS          string   `json:"pfs"`
}

func failOnError(err error, msg string) {
	if err != nil {
		log.Fatalf("%s: %s", msg, err)
		panic(fmt.Sprintf("%s: %s", msg, err))
	}
}

func panicIf(err error) bool {
	if err != nil {
		log.Println(fmt.Sprintf("%s", err))
		return true
	}

	return false
}

func (s ScanInfo) toConnInfo() (ConnectionInfo, error) {

	c := ConnectionInfo{}

	var err error

	c.ConnectionTimestamp = s.Timestamp
	c.ServerSide = false
	if s.ServerSide == "True" {
		c.ServerSide = true
	}

	for _, cipher := range s.CipherSuites {

		newcipher := ConnectionCiphersuite{}

		newcipher.Cipher = cipher.Cipher
		newcipher.OCSPStapling = false
		if cipher.OCSPStapling == "True" {
			newcipher.OCSPStapling = true
		}

		newcipher.PFS = cipher.PFS

		newcipher.Protocols = cipher.Protocols

		if len(cipher.PubKey) > 1 {
			log.Println("Multiple PubKeys for ", s.Target, " at cipher :", cipher.Cipher)
		}

		if len(cipher.PubKey) > 0 {
			newcipher.PubKey, err = strconv.ParseFloat(cipher.PubKey[0], 64)
		} else {
			return c, fmt.Errorf("No Public Keys found")
		}

		if len(cipher.SigAlg) > 1 {
			log.Println("Multiple SigAlgs for ", s.Target, " at cipher :", cipher.Cipher)
		}

		if len(cipher.SigAlg) > 0 {
			newcipher.SigAlg = cipher.SigAlg[0]
		} else {
			return c, fmt.Errorf("No Signature Algorithms found")
		}

		newcipher.TicketHint = cipher.TicketHint

		if err != nil {
			return c, err
		}

		c.CipherSuites = append(c.CipherSuites, newcipher)
	}

	return c, nil

}

//worker is the main body of the goroutine that handles each received message.
func worker(msgs <-chan []byte) {

	forever := make(chan bool)
	defer wg.Done()

	for d := range msgs {

		info := ScanInfo{}

		err := json.Unmarshal(d, &info)

		panicIf(err)

		if err != nil {
			continue
		}

		c, err := info.toConnInfo()

		panicIf(err)

		if err != nil {
			continue
		}

		id := info.Target

		jsonConn, err := json.Marshal(c)
		panicIf(err)

		if err != nil {
			continue
		}

		err = es.Push(esIndex, esType, id, jsonConn)
		panicIf(err)
	}

	<-forever
}

func printIntro() {
	fmt.Println(`
	##################################
	#         TLSAnalyzer            #
	##################################
	`)
}

var wg sync.WaitGroup

func main() {
	var (
		err error
	)

	printIntro()

	conf := config.AnalyzerConfig{}

	var cfgFile string
	flag.StringVar(&cfgFile, "c", "/etc/observer/analyzer.cfg", "Input file csv format")
	flag.Parse()

	_, err = os.Stat(cfgFile)
	failOnError(err, "Missing configuration file from '-c' or /etc/observer/retriever.cfg")

	conf, err = config.AnalyzerConfigLoad(cfgFile)
	if err != nil {
		conf = config.GetAnalyzerDefaults()
	}

	cores := runtime.NumCPU()
	runtime.GOMAXPROCS(cores * conf.General.GoRoutines)

	err = es.RegisterConnection(conf.General.ElasticSearch)

	failOnError(err, "Failed to register ElasticSearch")

	broker, err = amqpmodule.RegisterURL(conf.General.RabbitMQRelay)

	failOnError(err, "Failed to register RabbitMQ")

	msgs, err := broker.Consume(rxQueue)

	for i := 0; i < cores; i++ {
		wg.Add(1)
		go worker(msgs)
	}

	wg.Wait()
}
