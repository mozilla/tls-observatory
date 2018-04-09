package connection

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os/exec"
	"time"
)

type NoTLSConnErr string

func (f NoTLSConnErr) Error() string {
	return fmt.Sprintf("No TLS Conn Received")
}

func Connect(domain, cipherscanbinPath string) ([]byte, error) {
	ip := getRandomIP(domain)

	if ip == "" {
		e := fmt.Errorf("Could not resolve ip for: %s", domain)
		log.Println(e)
		return nil, e
	}

	cmd := cipherscanbinPath + " --no-tolerance -j --curves -servername " + domain + " " + ip + ":443 "
	log.Println(cmd)
	comm := exec.Command("bash", "-c", cmd)
	var out bytes.Buffer
	var stderr bytes.Buffer
	comm.Stdout = &out
	comm.Stderr = &stderr
	err := comm.Start()
	if err != nil {
		log.Println(stderr.String())
		log.Println(err)
		return nil, err
	}
	waiter := make(chan error, 1)
	go func() {
		waiter <- comm.Wait()
	}()
	select {
	case <-time.After(3 * time.Minute):
		err = fmt.Errorf("cipherscan timed out after 3 minutes on target %s %s", domain, ip)
		return nil, err
	case err := <-waiter:
		if err != nil {
			log.Println(err)
			return nil, err
		}
	}

	info := CipherscanOutput{}
	err = json.Unmarshal([]byte(out.String()), &info)
	if err != nil {
		log.Println(err)
		return nil, err
	}

	info.Target = domain
	info.IP = ip

	c, err := info.Stored()

	if err != nil {
		log.Println(err)
		return nil, err
	}

	return json.Marshal(c)
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
