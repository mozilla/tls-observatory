package sslLabsClientSupport

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/mozilla/tls-observatory/connection"
	"github.com/mozilla/tls-observatory/constants"
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
	Clients []Client
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
	IsSupported bool   `json:"is_supported"`
	Ciphersuite string `json:"ciphersuite,omitempty"`
	Code        int    `json:"code,omitempty"`
	Curve       string `json:"curve,omitempty"`
	Protocol    string `json:"protocol,omitempty"`
}

func (w slabscrunner) Run(in worker.Input, res chan worker.Result) {
	ClientsSupport := make(map[string]ClientSupport)
	// Loop over every client defined in the sslLabs document and check if they can
	// negotiate one of the ciphersuite measured on the server
	for _, client := range w.Clients {
		var cs ClientSupport
		for _, clientCiphersuite := range client.SuiteIds {
			for _, serverCiphersuite := range in.Connection.CipherSuite {
				serverCiphersuiteCode := constants.CipherSuites[serverCiphersuite.Cipher].Code
				if clientCiphersuite == int(serverCiphersuiteCode) {
					// if the ciphersuite is DHE, verify that the client support the DH size
					if strings.HasPrefix(serverCiphersuite.Cipher, "DHE-") &&
						client.MaxDhBits > 0 &&
						!clientSupportsDHE(client, serverCiphersuite) {
						continue
					}
					// if the ciphersuite is ECDHE, verify that the client supports the curve
					if strings.HasPrefix(serverCiphersuite.Cipher, "ECDHE-") && len(client.EllipticCurves) > 0 {
						cs.Curve = findClientCurve(client, serverCiphersuite)
						if cs.Curve == "" {
							continue
						}
					}
					cs.Protocol = findClientProtocol(client, serverCiphersuite)
					if cs.Protocol == "" {
						continue
					}
					// if we reached this point, the client is able to establish a connection
					// to the server. we flag it as supported and go to the next client.
					cs.IsSupported = true
					cs.Ciphersuite = serverCiphersuite.Cipher
					cs.Code = clientCiphersuite
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

func clientSupportsDHE(client Client, serverCiphersuite connection.Ciphersuite) bool {
	// extract the dhe bits from the pfs string
	split := strings.Split(serverCiphersuite.PFS, ",")
	if len(split) < 2 {
		return false
	}
	split = strings.Split(split[1], "b")
	if len(split) < 2 {
		return false
	}
	dhsize, err := strconv.Atoi(split[0])
	if err != nil {
		return false
	}
	if client.MaxDhBits < dhsize {
		return false
	}
	return true
}

func findClientCurve(client Client, serverCiphersuite connection.Ciphersuite) string {
	for _, code := range client.EllipticCurves {
		// convert curve code to name
		for _, curveRef := range constants.Curves {
			if int(curveRef.Code) == code {
				for _, serverCurves := range serverCiphersuite.Curves {
					if curveRef.Name == serverCurves || curveRef.OpenSSLName == serverCurves {
						return curveRef.Name
					}
				}
			}
		}
	}
	return ""
}

func findClientProtocol(client Client, serverCiphersuite connection.Ciphersuite) string {
	for _, serverProto := range serverCiphersuite.Protocols {
		var spcode int
		for _, proto := range constants.Protocols {
			if proto.OpenSSLName == serverProto {
				spcode = proto.Code
			}
		}
		if client.LowestProtocol <= spcode && client.HighestProtocol >= spcode {
			return serverProto
		}
	}
	return ""
}

func (w slabscrunner) error(res chan worker.Result, messageFormat string, args ...interface{}) {
	out, _ := json.Marshal(fmt.Sprintf(messageFormat, args...))
	res <- worker.Result{
		Success:    false,
		WorkerName: workerName,
		Result:     out,
	}
}
