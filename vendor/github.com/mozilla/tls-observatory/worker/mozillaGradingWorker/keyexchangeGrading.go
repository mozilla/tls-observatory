package mozillaGradingWorker

import (
	"math"
	"strconv"
	"strings"

	"github.com/mozilla/tls-observatory/connection"
	"github.com/mozilla/tls-observatory/constants"
	"github.com/sirupsen/logrus"
)

//ECCRSAKeySize is used to translate ECC keys length to their corresponding RSA ones
var ECCRSAKeySize = map[float64]float64{
	160: 1024,
	224: 2048,
	256: 3072,
	384: 7680,
	512: 15360,
}

//gradeKeyX uses the simple SSLLabs method to grade the key Exchange characteristics
//of the connection
func gradeKeyX(connInfo connection.Stored) (categoryResults, error) {
	res := categoryResults{}

	best := float64(0)
	worst := float64(15360)

	for _, cs := range connInfo.CipherSuite {

		pubkeylength := getBitsForPubKey(cs)

		bits := pubkeylength

		// if we do not have a Kx algorithm the public key length is enough
		if cs.PFS != "None" {
			kxlength := getBitsForKeyExchange(cs.PFS)
			bits = math.Min(pubkeylength, kxlength)
		}

		if bits < worst {
			worst = bits
		}
		if bits > best {
			best = bits
		}
	}

	res.Grade = getKxScoreFromBits((best + worst) / 2)

	return res, nil
}

func getBitsForPubKey(cs connection.Ciphersuite) float64 {

	cipher := cs.Cipher

	if c, ok := constants.CipherSuites[cipher]; ok {
		if c.Au == "ECDSA" {
			if b, ok := ECCRSAKeySize[cs.PubKey]; ok {
				return b
			}
		}
	} else {
		log.WithFields(logrus.Fields{
			"Ciphersuite": cs.Cipher,
		}).Warning("Not contained in OpenSSL ciphersuites")
	}
	return cs.PubKey
}

func getKxScoreFromBits(bits float64) int {
	if bits <= 0 {
		return 0
	} else if bits < 512 {
		return 20
	} else if bits < 1024 {
		return 40
	} else if bits < 2048 {
		return 80
	} else if bits < 4096 {
		return 90
	}
	return 100
}

func getBitsForKeyExchange(kx string) float64 {

	pfs := strings.Split(kx, ",")
	if len(pfs) < 2 {
		return 0
	}

	if "ECDH" == pfs[0] {
		bitsStr := strings.TrimRight(pfs[2], "bits")
		bits, err := strconv.ParseFloat(bitsStr, 64)
		if err != nil {
			return -1
		}
		if b, ok := ECCRSAKeySize[bits]; ok {
			return b
		}
		return -1
	} else if "DH" == pfs[0] {
		bitsStr := strings.TrimRight(pfs[1], "bits")

		bits, err := strconv.ParseFloat(bitsStr, 64)
		if err != nil {
			return -1
		}
		return bits
	}
	return 0
}
