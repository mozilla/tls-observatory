package sslLabsClientSupport

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/mozilla/scribe"
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
	worker.RegisterPrinter(workerName, worker.Info{Runner: runner, Description: workerDesc})
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
	Platform                 string   `json:"platform"`
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
	Name            string `json:"name"`
	Version         string `json:"version"`
	Platform        string `json:"platform"`
	IsSupported     bool   `json:"is_supported"`
	Ciphersuite     string `json:"ciphersuite,omitempty"`
	CiphersuiteCode uint64 `json:"ciphersuite_code,omitempty"`
	Curve           string `json:"curve,omitempty"`
	CurveCode       uint64 `json:"curve_code"`
	Protocol        string `json:"protocol,omitempty"`
	ProtocolCode    int    `json:"protocol_code"`
}

type ClientsSupport []ClientSupport

func (slice ClientsSupport) Len() int {
	return len(slice)
}

func (slice ClientsSupport) Less(i, j int) bool {
	return slice[i].Name < slice[j].Name
}

func (slice ClientsSupport) Swap(i, j int) {
	slice[i], slice[j] = slice[j], slice[i]
}

func (w slabscrunner) Run(in worker.Input, res chan worker.Result) {
	var clients ClientsSupport
	dedupClients := make(map[string]bool)
	// Loop over every client defined in the sslLabs document and check if they can
	// negotiate one of the ciphersuite measured on the server
	for _, client := range w.Clients {
		// if we already processed a client with this name, version and platform, skip it
		if _, ok := dedupClients[fmt.Sprintf("%s%s%s", client.Name, client.Version, client.Platform)]; ok {
			continue
		}
		for _, clientCiphersuite := range client.SuiteIds {
			for _, serverCiphersuite := range in.Connection.CipherSuite {
				serverCiphersuiteCode := constants.CipherSuites[serverCiphersuite.Cipher].Code
				if clientCiphersuite == int(serverCiphersuiteCode) {
					var (
						curve, protocol string
						curveCode       uint64
						protocolCode    int
					)
					// if the ciphersuite is DHE, verify that the client support the DH size
					if strings.HasPrefix(serverCiphersuite.Cipher, "DHE-") &&
						client.MaxDhBits > 0 &&
						!clientSupportsDHE(client, serverCiphersuite) {
						continue
					}
					// if the ciphersuite is ECDHE, verify that the client supports the curve
					if strings.HasPrefix(serverCiphersuite.Cipher, "ECDHE-") && len(client.EllipticCurves) > 0 {
						curve, curveCode = findClientCurve(client, serverCiphersuite)
						if curve == "" {
							continue
						}
					}
					protocol, protocolCode = findClientProtocol(client, serverCiphersuite)
					if protocol == "" {
						continue
					}
					// if we reached this point, the client is able to establish a connection
					// to the server. we flag it as supported and go to the next client.
					clients = append(clients, ClientSupport{
						Name:            client.Name,
						Version:         client.Version,
						Platform:        client.Platform,
						IsSupported:     true,
						Ciphersuite:     serverCiphersuite.Cipher,
						CiphersuiteCode: serverCiphersuite.Code,
						Curve:           curve,
						CurveCode:       curveCode,
						Protocol:        protocol,
						ProtocolCode:    protocolCode,
					})
					goto nextClient
				}
			}
		}
		// if we reach this point, it means no support was found for this client
		clients = append(clients, ClientSupport{
			Name:        client.Name,
			Version:     client.Version,
			IsSupported: false,
		})
	nextClient:
	}
	out, err := json.Marshal(clients)
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

func findClientCurve(client Client, serverCiphersuite connection.Ciphersuite) (string, uint64) {
	for _, code := range client.EllipticCurves {
		// convert curve code to name
		for _, curveRef := range constants.Curves {
			if int(curveRef.Code) == code {
				for _, serverCurves := range serverCiphersuite.Curves {
					if curveRef.Name == serverCurves || curveRef.OpenSSLName == serverCurves {
						return curveRef.Name, curveRef.Code
					}
				}
			}
		}
	}
	return "", 0
}

func findClientProtocol(client Client, serverCiphersuite connection.Ciphersuite) (string, int) {
	for _, serverProto := range serverCiphersuite.Protocols {
		var spcode int
		for _, proto := range constants.Protocols {
			if proto.OpenSSLName == serverProto {
				spcode = proto.Code
			}
		}
		if client.LowestProtocol <= spcode && client.HighestProtocol >= spcode {
			return serverProto, spcode
		}
	}
	return "", 0
}

func (w slabscrunner) error(res chan worker.Result, messageFormat string, args ...interface{}) {
	out, _ := json.Marshal(fmt.Sprintf(messageFormat, args...))
	res <- worker.Result{
		Success:    false,
		WorkerName: workerName,
		Result:     out,
	}
}

var number = regexp.MustCompile(`^[0-9]+$`)

func (w slabscrunner) AnalysisPrinter(r []byte, printAll interface{}) (results []string, err error) {
	var cs ClientsSupport
	err = json.Unmarshal(r, &cs)
	if err != nil {
		err = fmt.Errorf("SSLLabs Client Support: failed to parse results: %v", err)
		return
	}
	if printAll != nil && printAll.(bool) == true {
		results = append(results, "* SSLLabs Client Support: showing all clients compatibility")
	} else {
		results = append(results, "* SSLLabs Client Support: showing oldest known clients")
	}
	var productsSupport = make(map[string]ClientSupport)
	// sort the list of clients, it's nicer to display
	sort.Sort(cs)
	for _, client := range cs {
		// if we want all clients, store the result and go to next entry
		if printAll != nil && printAll.(bool) == true {
			result := fmt.Sprintf("  - %s %s", client.Name, client.Version)
			if client.Platform != "" {
				result += fmt.Sprintf(" (%s)", client.Platform)
			}
			if client.IsSupported {
				result += fmt.Sprintf(": yes, %s %s %s", client.Protocol, client.Ciphersuite, client.Curve)
			} else {
				result += fmt.Sprintf(": no")
			}
			results = append(results, result)
			continue
		}
		// Once we reach this point, we only want supported clients
		if !client.IsSupported {
			continue
		}
		// if we only want the oldest compatible client, some dark magic is required
		// to parse the version of each client, which varies in format, and figure out
		// the oldest
		if _, ok := productsSupport[client.Name]; !ok {
			// this is the first supported client of this name that we encounter,
			// no comparison needed, simply store it
			productsSupport[client.Name] = client
			continue
		}
		prevClient := productsSupport[client.Name]
		// compare the version of the previous and current clients,
		// if the current client is older, store it instead of the previous one
		isOlder, err := scribe.TestEvrCompare(scribe.EvropLessThan, client.Version, prevClient.Version)
		if err != nil {
			log.Printf("Failed to compare version %s with version %s for client %s: %v",
				client.Version, prevClient.Version, client.Name, err)
		}
		if isOlder {
			productsSupport[client.Name] = client
		}
	}
	if printAll != nil && printAll.(bool) == true {
		// if we just want to print all clients, return here
		return
	}
	// if we only want the oldest client, build the list here
	var supportedClients []string
	for _, clientName := range []string{"Firefox", "Chrome", "Edge", "IE", "Safari", "Opera", "Android", "OpenSSL", "Java"} {
		client := productsSupport[clientName]
		result := fmt.Sprintf("%s %s", client.Name, client.Version)
		supportedClients = append(supportedClients, result)
	}
	results = append(results, fmt.Sprintf("  - %s", strings.Join(supportedClients, ", ")))
	return
}
