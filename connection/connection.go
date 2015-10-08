package connection

import (
	"fmt"
	"log"
	"reflect"
	"strconv"
	"time"
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
	Curves       []string `json:"curves,omitempty"`
}

//the following structs represent the output we want to provide to DB.

type Stored struct {
	ScanTarget         string                       `json:"scanTarget"`
	ScanIP             string                       `json:"scanIP"`
	FirstSeenTimestamp string                       `json:"firstSeenTimestamp"`
	LastSeenTimestamp  string                       `json:"lastSeenTimestamp"`
	ServerSide         bool                         `json:"serverside"`
	CipherSuites       map[string]StoredCiphersuite `json:"cipherscanCiphersuite"`
	CurvesFallback     bool                         `json:"curvesFallback"`
	ObsoletedBy        string                       `json:"obsoletedBy,omitempty"`
}

type StoredCiphersuite struct {
	Cipher       string   `json:"cipher"`
	Protocols    []string `json:"protocols"`
	PubKey       float64  `json:"pubkey"`
	SigAlg       string   `json:"sigalg"`
	TicketHint   string   `json:"ticket_hint"`
	OCSPStapling bool     `json:"ocsp_stapling"`
	PFS          string   `json:"pfs"`
	Curves       []string `json:"curves,omitempty"`
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

	for pos, suite := range c.CipherSuites {

		if !suite.equal(ci.CipherSuites[pos]) {
			return false
		}
	}

	return true
}

func (s StoredCiphersuite) equal(cs StoredCiphersuite) bool {

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

func (s CipherscanOutput) Stored() (Stored, error) {

	c := Stored{}

	var err error

	t, err := s.convertTimestamp(s.Timestamp)

	if err != nil {
		return c, err
	}

	timestamp := fmt.Sprintf("%d-%02d-%02dT%02d:%02d:%02d", t.UTC().Year(), t.UTC().Month(), t.UTC().Day(), t.UTC().Hour(), t.UTC().Minute(), t.UTC().Second())

	c.FirstSeenTimestamp = timestamp
	c.LastSeenTimestamp = timestamp
	c.ServerSide = stringtoBool(s.ServerSide)
	c.CurvesFallback = stringtoBool(s.CurvesFallback)
	c.ScanTarget = s.Target
	c.ScanIP = s.IP

	c.CipherSuites = make(map[string]StoredCiphersuite)

	pos := 1

	for _, cipher := range s.CipherSuites {

		newcipher := StoredCiphersuite{}

		newcipher.Cipher = cipher.Cipher
		newcipher.OCSPStapling = stringtoBool(cipher.OCSPStapling)
		newcipher.PFS = cipher.PFS

		newcipher.Protocols = cipher.Protocols

		if len(cipher.PubKey) > 1 {
			log.Println("Multiple PubKeys for ", s.Target, " at cipher :", cipher.Cipher)
		}

		if len(cipher.PubKey) > 0 {
			newcipher.PubKey, err = strconv.ParseFloat(cipher.PubKey[0], 64)
		} else {
			return c, fmt.Errorf("No Public Keys found")
		}

		if len(cipher.SigAlg) > 1 {
			log.Println("Multiple SigAlgs for ", s.Target, " at cipher :", cipher.Cipher)
		}

		if len(cipher.SigAlg) > 0 {
			newcipher.SigAlg = cipher.SigAlg[0]
		} else {
			return c, fmt.Errorf("No Signature Algorithms found")
		}

		newcipher.TicketHint = cipher.TicketHint

		if err != nil {
			return c, err
		}

		newcipher.Curves = append(newcipher.Curves, cipher.Curves...)

		c.CipherSuites[strconv.Itoa(pos)] = newcipher
		pos++
	}

	return c, nil
}
