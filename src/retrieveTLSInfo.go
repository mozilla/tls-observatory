package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"github.com/streadway/amqp"
	"io"
	"os"
	"time"
)

var programName = "tlsRetriever"

func Usage() {
	fmt.Printf("Usage: %s -d <domain name> -p <port> -i <input csv>\n", programName)
	flag.PrintDefaults()
}

func panicIf(err error) {
	if err != nil {
		panic(fmt.Sprintf("%s", err))
	}
}

func main() {
	var domainName, port, infile string

	flag.StringVar(&domainName, "d", "", "Domain name or IP Address of the host you want to check ssl certificates of.")
	flag.StringVar(&port, "p", "443", "Port Number")
	flag.StringVar(&infile, "i", "", "Input file csv format")
	flag.Parse()

	if len(os.Args) < 3 || ((domainName == "") && (infile == "")) {
		Usage()
		os.Exit(1)
	}

	conn, err := amqp.Dial("amqp://guest:guest@localhost:5672/")
	panicIf(err)
	defer conn.Close()

	ch, err := conn.Channel()
	panicIf(err)
	defer ch.Close()

	_, err = ch.QueueDeclare(
		"scan_ready_queue", // name
		true,               // durable
		false,              // delete when unused
		false,              // exclusive
		false,              // no-wait
		nil,                // arguments
	)
	panicIf(err)

	err = ch.Qos(
		3,     // prefetch count
		0,     // prefetch size
		false, // global
	)
	panicIf(err)

	if infile != "" {

		file, _ := os.Open(infile)

		defer file.Close()
		//
		reader := csv.NewReader(file)

		// options are available at:
		// http://golang.org/src/pkg/encoding/csv/reader.go?s=3213:3671#L94
		reader.Comma = ','
		lineCount := 0
		for {
			// read just one record, but we could ReadAll() as well
			record, err := reader.Read()
			// end-of-file is fitted into err
			if err == io.EOF {
				break
			} else if err != nil {
				fmt.Println("Error:", err)
				break
			}

			var domain string
			domain = record[len(record)-1]

			err = ch.Publish(
				"",                 // exchange
				"scan_ready_queue", // routing key
				false,              // mandatory
				false,
				amqp.Publishing{
					DeliveryMode: amqp.Persistent,
					ContentType:  "text/plain",
					Body:         []byte(domain),
				})
			panicIf(err)

			lineCount += 1
			time.Sleep(5 * time.Millisecond)
		}
	} else {

		err = ch.Publish(
			"",                 // exchange
			"scan_ready_queue", // routing key
			false,              // mandatory
			false,
			amqp.Publishing{
				DeliveryMode: amqp.Persistent,
				ContentType:  "text/plain",
				Body:         []byte(domainName),
			})
		panicIf(err)

	}
}
