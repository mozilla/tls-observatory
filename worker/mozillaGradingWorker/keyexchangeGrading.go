package mozillaGradingWorker

import (
	"strconv"
	"strings"
	"fmt"

	"github.com/mozilla/tls-observatory/connection"
)

var ECCRSAKeySize = map[float64]float64{
	160: 1024,
	224: 2048,
	256: 3072,
	384: 7680,
	512: 15360,
}

func gradeKeyX(connInfo connection.Stored) (categoryResults, error) {
	res := categoryResults{}

	best := float64(0)
	worst := float64(15360)

	fmt.Println(len(connInfo.CipherSuite))

	for _, cs := range connInfo.CipherSuite {

		pubkeylength := getBitsForPubKey(cs)

		kxlength := getBitsForKeyExchange(cs.PFS)

		fmt.Println(cs.Cipher)

		fmt.Println(pubkeylength)
		fmt.Println(kxlength)
		fmt.Println("~~~~~~~~~~~~~~~~~")

		bits := min(pubkeylength, kxlength)

		if bits < worst {
			worst = bits
		}
		if bits > best {
			best = bits
		}
	}

	fmt.Println(best)
	fmt.Println(worst)
	fmt.Println("========")

	res.Grade = getKxScoreFromBits((best + worst) / 2)

	return res, nil
}

func getBitsForPubKey(cs connection.Ciphersuite) float64 {

	cipher := cs.Cipher

	if c, ok := opensslciphersuites[cipher]; ok {
		if c.Au == "ECDSA"{
			if b, ok := ECCRSAKeySize[cs.PubKey]; ok {
				return b
			}
		}
	}
	return cs.PubKey

}

func getKxScoreFromBits(bits float64) int {
	if bits <= 0 {
		return 0
	}else if bits < 512 {
		return 20 
	}else if bits < 1024 {
		return 40
	}else if bits < 2048 { 
		return 80
	}else if bits < 4096 {
		return 90
	}else {
		return 100
	}
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

func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
