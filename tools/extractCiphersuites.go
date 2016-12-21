package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

type Cipher struct {
	IANAName   string     `json:"iana_name"`
	GnuTLSName string     `json:"gnutls_name"`
	NSSName    string     `json:"nss_name"`
	Proto      string     `json:"proto"`
	Kx         string     `json:"kx"`
	Au         string     `json:"au"`
	Enc        Encryption `json:"encryption"`
	Mac        string     `json:"mac"`
	Code       uint64     `json:"code"`
}

type Encryption struct {
	Cipher string `json:"cipher"`
	Bits   int    `json:"key"`
}

type CiphersuiteNames struct {
	GnuTLS  string `json:"GnuTLS"`
	NSS     string `json:"NSS"`
	IANA    string `json:"IANA"`
	OpenSSL string `json:"OpenSSL"`
}

func main() {
	csnames := make(map[string]CiphersuiteNames)
	gopath := os.Getenv("GOPATH")
	csnamesfd, err := ioutil.ReadFile(gopath + "/src/github.com/mozilla/tls-observatory/tools/ciphersuites_names.json")
	if err != nil {
		log.Fatalf("Failed to read ciphersuites name file: %v", err)
	}
	err = json.Unmarshal(csnamesfd, &csnames)
	if err != nil {
		log.Fatalf("Failed to parse ciphersuites names: %v", err)
	}
	comm := exec.Command("/opt/cipherscan/openssl", "ciphers", "-V")
	var out bytes.Buffer
	var stderr bytes.Buffer
	comm.Stdout = &out
	comm.Stderr = &stderr
	err = comm.Run()
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
		l = strings.Trim(l, " ")
		// output format from openssl ciphers -V is
		// 0xCC,0x14 - ECDHE-ECDSA-CHACHA20-POLY1305-OLD TLSv1.2 Kx=ECDH     Au=ECDSA Enc=ChaCha20(256) Mac=AEAD
		// ^code       ^ ciphersuite name                ^version  ^kx       ^Au      ^Enc Cipher  Bits ^Mac
		//  0              2                                3       4         5             6             7
		line := strings.Fields(l)
		encbits, err := strconv.Atoi(strings.TrimRight(strings.Split(strings.Split(line[6], "=")[1], "(")[1], ")"))
		if err != nil {
			log.Fatalf("Could not get encryption bits, %s", err)
		}
		enc := Encryption{
			Cipher: strings.Split(strings.Split(line[6], "=")[1], "(")[0],
			Bits:   encbits,
		}
		codeComps := strings.Split(line[0], ",")
		code, err := strconv.ParseUint(strings.Split(codeComps[0], "x")[1]+strings.Split(codeComps[1], "x")[1], 16, 64)
		if err != nil {
			log.Fatalf("Failed to parse code point for line %q: %v", l, err)
		}
		c := Cipher{
			IANAName:   csnames[line[0]].IANA,
			GnuTLSName: csnames[line[0]].GnuTLS,
			NSSName:    csnames[line[0]].NSS,
			Proto:      line[3],
			Kx:         strings.Split(line[4], "=")[1],
			Au:         strings.Split(line[5], "=")[1],
			Enc:        enc,
			Mac:        strings.Split(line[7], "=")[1],
			Code:       code,
		}
		ciphers[line[2]] = c
	}

	js, _ := json.MarshalIndent(&ciphers, "", "	")
	if len(os.Args) > 1 && os.Args[1] == "mozillaGradingWorker" {
		//recreate the file ciphersuites.go
		content := fmt.Sprintf("package mozillaGradingWorker\n//go:generate go run $GOPATH/src/github.com/mozilla/tls-observatory/tools/extractCiphersuites.go mozillaGradingWorker\nvar OpenSSLCiphersuites = `%s`", string(js))
		err = ioutil.WriteFile("ciphersuites.go", []byte(content), 0777)
		if err != nil {
			log.Println(err)
		}
		fmt.Fprintf(os.Stderr, "output written to ./ciphersuite.go\n")
	} else if len(os.Args) > 1 && os.Args[1] == "sslLabsClientSupport" {
		//recreate the file ciphersuites.go
		content := fmt.Sprintf("package sslLabsClientSupport\n//go:generate go run $GOPATH/src/github.com/mozilla/tls-observatory/tools/extractCiphersuites.go sslLabsClientSupport\nvar OpenSSLCiphersuites = `%s`", string(js))
		err = ioutil.WriteFile("ciphersuites.go", []byte(content), 0777)
		if err != nil {
			log.Println(err)
		}
		fmt.Fprintf(os.Stderr, "output written to ./ciphersuite.go\n")
	} else {
		fmt.Printf("%s\n", js)
	}
}
