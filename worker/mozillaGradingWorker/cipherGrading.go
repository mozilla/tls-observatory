package mozillaGradingWorker

import (
	"github.com/mozilla/tls-observatory/connection"
	"github.com/mozilla/tls-observatory/constants"
)

func gradeCiphers(connInfo connection.Stored) (categoryResults, error) {
	res := categoryResults{}

	best := 0
	worst := 0

	for _, cs := range connInfo.CipherSuite {
		cipher := cs.Cipher
		if c, ok := constants.CipherSuites[cipher]; ok {
			if c.Enc.Bits > best {
				best = c.Enc.Bits
			}
			if c.Enc.Bits < worst {
				worst = c.Enc.Bits
			}
		}
	}

	res.Grade = (getScoreFromBits(best) + getScoreFromBits(worst)) / 2
	return res, nil
}

func getScoreFromBits(bits int) int {
	score := 0
	if 0 < bits && bits < 128 {
		score = 20
	} else if bits < 256 {
		score = 80
	} else {
		score = 100
	}
	return score
}
