package connection

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os/exec"
)

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

func Connect(domain string) {

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

	info.Target = domain
	info.IP = ip

	processConnection(info.Stored())

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
