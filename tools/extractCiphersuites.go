package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os/exec"
	"strconv"
	"strings"
)

type Cipher struct {
	// Name  string     `json:"name"`
	Proto string     `json:"proto"`
	Kx    string     `json:"kx"`
	Au    string     `json:"au"`
	Enc   Encryption `json:"encryption"`
	Mac   string     `json:"mac"`
}

type Encryption struct {
	Cipher string `json:"cipher"`
	Bits   int    `json:"key"`
}

var opensslpath = "/opt/cipherscan/openssl"

func main() {
	cmd := opensslpath + " ciphers -v"
	comm := exec.Command("bash", "-c", cmd)
	var out bytes.Buffer
	var stderr bytes.Buffer
	comm.Stdout = &out
	comm.Stderr = &stderr
	err := comm.Run()
	if err != nil {
		log.Println(err)
		return
	}

	ciphers := make(map[string]Cipher)

	lines := strings.Split(out.String(), "\n")
	for _, l := range lines {
		if l == "" {
			break
		}
		line := strings.Fields(l)
		encbits, err := strconv.Atoi(strings.TrimRight(strings.Split(strings.Split(line[4], "=")[1], "(")[1], ")"))
		if err != nil {
			fmt.Errorf("Could not get encryption bits, %s", err)
			return
		}
		enc := Encryption{
			Cipher: strings.Split(strings.Split(line[4], "=")[1], "(")[0],
			Bits:   encbits,
		}
		c := Cipher{
			Proto: line[1],
			Kx:    strings.Split(line[2], "=")[1],
			Au:    strings.Split(line[3], "=")[1],
			Enc:   enc,
			Mac:   strings.Split(line[5], "=")[1],
		}
		ciphers[line[0]] = c
	}

	js, _ := json.MarshalIndent(&ciphers, "", "	")
	//recreate the file ciphersuites.go
	content := fmt.Sprintf("package mozillaGradingWorker\n\nvar OpenSSLCiphersuites = `%s`", string(js))
	err = ioutil.WriteFile("ciphersuites.go", []byte(content), 0777)
	if err != nil {
		log.Println(err)
	}
}
