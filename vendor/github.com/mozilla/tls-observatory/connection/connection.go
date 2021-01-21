package connection

import (
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"time"

	"github.com/mozilla/tls-observatory/constants"
)

//following two structs represent cipherscan output

type CipherscanOutput struct {
	Target         string                  `json:"target"`
	IP             string                  `json:"ip"`
	Timestamp      string                  `json:"utctimestamp"`
	ServerSide     string                  `json:"serverside"`
	CurvesFallback string                  `json:"curves_fallback"`
	CipherSuites   []CipherscanCiphersuite `json:"ciphersuite"`
}

type CipherscanCiphersuite struct {
	Cipher       string   `json:"cipher"`
	Protocols    []string `json:"protocols"`
	PubKey       []string `json:"pubkey"`
	SigAlg       []string `json:"sigalg"`
	Trusted      string   `json:"trusted"`
	TicketHint   string   `json:"ticket_hint"`
	OCSPStapling string   `json:"ocsp_stapling"`
	PFS          string   `json:"pfs"`
	Curves       []string `json:"curves"`
}

//the following structs represent the output we want to provide to DB.

type Stored struct {
	ScanIP         string        `json:"scanIP"`
	ServerSide     bool          `json:"serverside"`
	CipherSuite    []Ciphersuite `json:"ciphersuite"`
	CurvesFallback bool          `json:"curvesFallback"`
}

type Ciphersuite struct {
	Cipher       string   `json:"cipher"`
	Code         uint64   `json:"code"`
	Protocols    []string `json:"protocols"`
	PubKey       float64  `json:"pubkey"`
	SigAlg       string   `json:"sigalg"`
	TicketHint   string   `json:"ticket_hint"`
	OCSPStapling bool     `json:"ocsp_stapling"`
	PFS          string   `json:"pfs"`
	Curves       []string `json:"curves"`
}

func stringtoBool(s string) bool {
	if s == "True" {
		return true
	} else {
		return false
	}
}

func (c Stored) Equal(ci Stored) bool {

	if c.CurvesFallback != ci.CurvesFallback {
		return false
	}

	if c.ServerSide != ci.ServerSide {
		return false
	}

	for i, suite := range c.CipherSuite {

		if !suite.equal(ci.CipherSuite[i]) {
			return false
		}
	}

	return true
}

func (s Ciphersuite) equal(cs Ciphersuite) bool {

	if s.Cipher != cs.Cipher {
		return false
	}

	if s.OCSPStapling != cs.OCSPStapling {
		return false
	}

	if s.PFS != cs.PFS {
		return false
	}

	if s.PubKey != cs.PubKey {
		return false
	}

	if s.SigAlg != cs.SigAlg {
		return false
	}

	if !reflect.DeepEqual(s.Curves, cs.Curves) {
		return false
	}

	if !reflect.DeepEqual(s.Protocols, cs.Protocols) {
		return false
	}

	return true

}

func (s CipherscanOutput) convertTimestamp(t string) (time.Time, error) {

	layout := "2006-01-02T15:04:05.0Z"
	return time.Parse(layout, t)
}

// Stored creates a Stored struct from the CipherscanOutput struct
func (s CipherscanOutput) Stored() (Stored, error) {

	c := Stored{}

	var err error

	c.ServerSide = stringtoBool(s.ServerSide)
	c.CurvesFallback = stringtoBool(s.CurvesFallback)
	c.ScanIP = s.IP

	for _, cipher := range s.CipherSuites {

		newcipher := Ciphersuite{}

		newcipher.Cipher = cipher.Cipher
		newcipher.Code = constants.CipherSuites[cipher.Cipher].Code
		newcipher.OCSPStapling = stringtoBool(cipher.OCSPStapling)
		newcipher.PFS = cipher.PFS

		newcipher.Protocols = cipher.Protocols

		if len(cipher.PubKey) > 1 {
			return c, fmt.Errorf("Multiple PubKeys for %s at cipher : %s", s.Target, cipher.Cipher)
		}

		if len(cipher.PubKey) > 0 {
			newcipher.PubKey, err = strconv.ParseFloat(cipher.PubKey[0], 64)
		} else {
			return c, errors.New("No Public Keys found")
		}

		if len(cipher.SigAlg) > 1 {

			return c, fmt.Errorf("Multiple SigAlgs for %s at cipher: %s", s.Target, cipher.Cipher)
		}

		if len(cipher.SigAlg) > 0 {
			newcipher.SigAlg = cipher.SigAlg[0]
		} else {
			return c, errors.New("No Signature Algorithms found")
		}

		newcipher.TicketHint = cipher.TicketHint
		if err != nil {
			return c, err
		}

		newcipher.Curves = append(newcipher.Curves, cipher.Curves...)
		c.CipherSuite = append(c.CipherSuite, newcipher)
	}

	return c, nil
}
