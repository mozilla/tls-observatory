package mozillaGradingWorker

import (
	"strconv"
	"strings"

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
	worst := float64(0)

	for _, cs := range connInfo.CipherSuite {

		pubkeylength := cs.PubKey

		kxlength := getBitsForKeyExchange(cs.PFS)

		score := min(pubkeylength, kxlength)

		if score < worst {
			worst = score
		}
		if score > best {
			best = score
		}
	}

	res.Grade = int((best + worst) / 2)

	return res, nil
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
