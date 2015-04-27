package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"runtime"
	"time"

	"connection"
	"modules/amqpmodule"

	"config"
)

const rxQueue = "tls_rx_queue"
const txQueue = "conn_scan_results_queue"
const txRoutKey = "conn_scan_results"
const rxRoutKey = "scan_ready"

var workerCount int
var broker *amqpmodule.Broker
var cipherscan string

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

func printIntro() {
	fmt.Println(`
	##################################
	#         TLSRetriever          #
	##################################
	`)
}

func reduceWC() {
	workerCount--
}

func worker(msg []byte) {

	defer reduceWC()

	domain := string(msg)
	ip := getRandomIP(domain)

	if ip == "" {
		log.Println("Could not resolve ip for: ", domain)
		return
	}

	cmd := cipherscan + " -j --curves -servername " + domain + " " + ip + ":443 "
	fmt.Println(cmd)
	comm := exec.Command("bash", "-c", cmd)
	var out bytes.Buffer
	var stderr bytes.Buffer
	comm.Stdout = &out
	comm.Stderr = &stderr
	err := comm.Run()
	if err != nil {
		log.Println(err)
	}

	info := connection.CipherscanOutput{}
	err = json.Unmarshal([]byte(out.String()), &info)
	if err != nil {
		log.Println(err)
		//should we requeue the domain???
		return
	}

	info.Target = domain + "--" + ip

	jsonInfo, err := json.MarshalIndent(info, "", "    ")
	panicIf(err)

	err = broker.Publish(txQueue, txRoutKey, []byte(jsonInfo))

	panicIf(err)
}

func getRandomIP(domain string) string {
	ips, err := net.LookupIP(domain)
	if err != nil {
		return ""
	}

	max := len(ips)

	for {
		if max == 0 {
			return ""
		}
		index := rand.Intn(len(ips))

		if ips[index].To4() != nil {
			return ips[index].String()
		} else {
			ips = append(ips[:index], ips[index+1:]...)
		}
		max--
	}
}

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
	flag.StringVar(&cipherscan, "b", "etc/observer/cipherscan", "Cipherscan binary to be used")
	flag.Parse()

	_, err = os.Stat(cfgFile)
	failOnError(err, "Missing configuration file from '-c' or /etc/observer/retriever.cfg")

	conf, err = config.RetrieverConfigLoad(cfgFile)
	if err != nil {
		conf = config.GetRetrieverDefaults()
	}

	_, err = os.Stat(cipherscan)
	failOnError(err, "Could not find ciphercan binary.")

	broker, err = amqpmodule.RegisterURL(conf.General.RabbitMQRelay)

	failOnError(err, "Failed to register RabbitMQ")

	msgs, err := broker.Consume(rxQueue, rxRoutKey)

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
