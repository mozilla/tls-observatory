package sslLabsClientSupport

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/mozilla/tls-observatory/logger"
	"github.com/mozilla/tls-observatory/worker"
)

var (
	workerName           = "sslLabsClientSupport"
	workerDesc           = "Determines client compatibility with a given target based on server certificate and ciphersuites."
	sslLabsClientDataURL = "https://api.ssllabs.com/api/v3/getClients"
	log                  = logger.GetLogger()
)

func init() {
	runner := new(slabscrunner)
	cs, err := getConffromURL(sslLabsClientDataURL)
	if err != nil {
		log.Printf("Failed to initialize %s: %v", workerName, err)
		return
	}
	runner.Clients = cs

	err = json.Unmarshal([]byte(OpenSSLCiphersuites), &runner.CipherSuites)
	if err != nil {
		log.Printf("Could not load OpenSSL ciphersuites: %v", err)
		return
	}
	worker.RegisterWorker(workerName, worker.Info{Runner: runner, Description: workerDesc})
}

// getClientDataFrom retrieves the json containing the sslLabs client data
func getConffromURL(url string) (cs []Client, err error) {
	r, err := http.Get(url)
	if err != nil {
		return
	}
	defer r.Body.Close()
	err = json.NewDecoder(r.Body).Decode(&cs)
	return
}

type slabscrunner struct {
	Clients      []Client
	CipherSuites map[string]CipherSuite
}

// Client is a definition of a TLS client with all the parameters it supports
type Client struct {
	ID                       int      `json:"id"`
	Name                     string   `json:"name"`
	Version                  string   `json:"version"`
	HandshakeFormat          string   `json:"handshakeFormat"`
	LowestProtocol           int      `json:"lowestProtocol"`
	HighestProtocol          int      `json:"highestProtocol"`
	UserAgent                string   `json:"userAgent"`
	IsGrade0                 bool     `json:"isGrade0"`
	MaxDhBits                int      `json:"maxDhBits"`
	AbortsOnUnrecognizedName bool     `json:"abortsOnUnrecognizedName"`
	MaxRsaBits               int      `json:"maxRsaBits"`
	MinDhBits                int      `json:"minDhBits"`
	RequiresSha2             bool     `json:"requiresSha2"`
	MinRsaBits               int      `json:"minRsaBits"`
	MinEcdsaBits             int      `json:"minEcdsaBits"`
	SuiteIds                 []int    `json:"suiteIds"`
	SuiteNames               []string `json:"suiteNames"`
	SupportsSni              bool     `json:"supportsSni"`
	SupportsCompression      bool     `json:"supportsCompression"`
	SupportsStapling         bool     `json:"supportsStapling"`
	SupportsTickets          bool     `json:"supportsTickets"`
	SupportsRi               bool     `json:"supportsRi"`
	SignatureAlgorithms      []int    `json:"signatureAlgorithms"`
	EllipticCurves           []int    `json:"ellipticCurves"`
	SupportsNpn              bool     `json:"supportsNpn"`
	NpnProtocols             []string `json:"npnProtocols"`
	AlpnProtocols            []string `json:"alpnProtocols"`
}

// CipherSuite represent a ciphersuite generated and recognised by OpenSSL
type CipherSuite struct {
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

//Encryption represents the encryption aspects of a Ciphersuite
type Encryption struct {
	Cipher string `json:"cipher"`
	Bits   int    `json:"key"`
}

type ClientSupport struct {
	IsSupported               bool   `json:"isSupported"`
	NegotiatedCiphersuite     string `json:"negotiatedCiphersuite,omitempty"`
	NegotiatedCiphersuiteCode int    `json:"negotiatedCiphersuiteCode,omitempty"`
}

func (w slabscrunner) Run(in worker.Input, res chan worker.Result) {
	ClientsSupport := make(map[string]ClientSupport)
	for _, client := range w.Clients {
		var cs ClientSupport
		for _, clientCiphersuite := range client.SuiteIds {
			for _, serverCiphersuite := range in.Connection.CipherSuite {
				serverCiphersuiteCode := w.CipherSuites[serverCiphersuite.Cipher].Code
				if clientCiphersuite == int(serverCiphersuiteCode) {
					cs.IsSupported = true
					cs.NegotiatedCiphersuite = serverCiphersuite.Cipher
					cs.NegotiatedCiphersuiteCode = clientCiphersuite
					goto nextClient
				}
			}
		}
	nextClient:
		ClientsSupport[fmt.Sprintf("%s %s", client.Name, client.Version)] = cs
	}
	out, err := json.Marshal(ClientsSupport)
	if err != nil {
		w.error(res, "Failed to marshal results: %v", err)
	}
	res <- worker.Result{
		Success:    true,
		WorkerName: workerName,
		Errors:     nil,
		Result:     out,
	}
}

func (w slabscrunner) error(res chan worker.Result, messageFormat string, args ...interface{}) {
	out, _ := json.Marshal(fmt.Sprintf(messageFormat, args...))
	res <- worker.Result{
		Success:    false,
		WorkerName: workerName,
		Result:     out,
	}
}
