package mozillaGradingWorker

import "github.com/mozilla/tls-observatory/connection"

func gradeCiphers(connInfo connection.Stored) (categoryResults, error) {
	res := categoryResults{}

	best := 0
	worst := 0

	RC4Support := false
	otherthanRC4 := false
	RC4withTLSv11 := false

	for _, cs := range connInfo.CipherSuite {

		cipher := cs.Cipher

		if c, ok := opensslciphersuites[cipher]; ok {
			if c.Enc.Bits > best {
				best = c.Enc.Bits
			}

			if c.Enc.Bits < worst {
				worst = c.Enc.Bits
			}

			if c.Enc.Cipher == "RC4" {
				RC4Support = true
				if contains(cs.Protocols, "TLSv1.1") || contains(cs.Protocols, "TLSv1.2"){
					RC4withTLSv11 = true
				}
			}else{
				otherthanRC4 = true
			}
		}
	}

	if RC4Support {
		if RC4withTLSv11 {
			res.Remarks = append(res.Remarks, "RC4 with TLSv1.1+, Grade capped to C")
		}else{ 
			res.Remarks = append(res.Remarks, "RC4 Ciphers supported, grade capped to B")
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
