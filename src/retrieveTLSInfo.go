package main

import (
	"flag"
	"fmt"
	"os"
	"github.com/goinggo/jobpool"
	"time"
	"log"
	"io/ioutil"
	"encoding/csv"
	"io"


	"github.com/mozilla/MWoSTLSObservatory/tlsretriever"
)

var programName = "tlsRetriever"

func Usage() {
	fmt.Printf("Usage: %s -d <domain name> -p <port> -i <input csv>\n", programName)
	flag.PrintDefaults()
}


type WorkProvider1 struct {
	    Domain string
	    Port   string
}

func (jobPool *WorkProvider1) RunJob(jobRoutine int) {

    log.Printf("Started: %s\n", jobPool.Domain)
    tlsretriever.Retrieve(jobPool.Domain, jobPool.Port)
    log.Printf("DONE: %s\n", jobPool.Port)
}

func init() {
	//Can be commented out to enable std Output logging
    log.SetOutput(ioutil.Discard)
}

func main(){
	var domainName, port, infile string

	flag.StringVar(&domainName, "d", "", "Domain name or IP Address of the host you want to check ssl certificates of.")
	flag.StringVar(&port, "p", "443", "Port Number")
	flag.StringVar(&infile, "i", "", "Input file csv format")
	flag.Parse()

	if len(os.Args) < 3 || ((domainName == "") && (infile == ""))  {
		Usage()
		os.Exit(1)
	}

	jobPool := jobpool.New(2, 1000)

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

			jobPool.QueueJob("main", &WorkProvider1{domain,port}, false)

			lineCount += 1
		}
	}else{

		jobPool.QueueJob("main", &WorkProvider1{domainName,port}, false)
	}

    for {
    	if jobPool.ActiveRoutines() == 0 {
    		break
    	}
    	time.Sleep(time.Millisecond)
    }

    defer jobPool.Shutdown("main")
}