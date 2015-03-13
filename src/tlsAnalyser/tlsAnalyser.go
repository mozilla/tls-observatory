package main

import (
	// stdlib packages

	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"sync"

	// custom packages
	"config"
	"modules/amqpmodule"
	es "modules/elasticsearchmodule"
)

const rxQueue = "conn_scan_results_queue"
const esIndex = "connections"
const esType = "connectionInfo"

var broker *amqpmodule.Broker

type ScanInfo struct {
	Target       string        `json:"target"`
	Timestamp    string        `json:"utctimestamp"`
	ServerSide   bool          `json:"serverside"`
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

type ConnectionInfo struct {
	ConnectionTimestamp string        `json:"connectionTimestamp"`
	ServerSide          bool          `json:"serverside"`
	CipherSuites        []Ciphersuite `json:"ciphersuite"`
}

type ConnectionCiphersuite struct {
	Cipher       string    `json:"cipher"`
	Protocols    []string  `json:"protocols"`
	PubKey       []float64 `json:"pubkey"`
	SigAlg       []string  `json:"sigalg"`
	TicketHint   float64   `json:"ticket_hint"`
	OCSPStapling bool      `json:"ocsp_stapling"`
	PFS          string    `json:"pfs"`
}

func failOnError(err error, msg string) {
	if err != nil {
		log.Fatalf("%s: %s", msg, err)
		panic(fmt.Sprintf("%s: %s", msg, err))
	}
}

func SHA256Hash(data []byte) string {
	h := sha256.New()
	h.Write(data)
	return fmt.Sprintf("%X", h.Sum(nil))
}

func panicIf(err error) bool {
	if err != nil {
		log.Println(fmt.Sprintf("%s", err))
		return true
	}

	return false
}

func (s ScanInfo) toConnInfo() ConnectionInfo {

	c := ConnectionInfo{}
	return c

}

//worker is the main body of the goroutine that handles each received message.
func worker(msgs <-chan []byte) {

	forever := make(chan bool)
	defer wg.Done()

	for d := range msgs {

		info := ScanInfo{}

		err := json.Unmarshal(d, &info)

		panicIf(err)

		c := info.toConnInfo()

		id := info.Target

		jsonConn, err := json.Marshal(c)
		panicIf(err)

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
