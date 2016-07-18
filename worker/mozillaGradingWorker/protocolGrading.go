package mozillaGradingWorker

import "github.com/mozilla/tls-observatory/connection"

const (
	sslv2  = 0
	sslv3  = 80
	tlsv1  = 90
	tlsv11 = 95
	tlsv12 = 100
)

func gradeProtocol(connInfo connection.Stored) (categoryResults, error) {

	res := categoryResults{}
	var allProtos []string
	for _, cs := range connInfo.CipherSuite {

		if contains(cs.Protocols, "SSLv2") {
			res.Grade = 0
			res.MaximumAllowed = 0
			res.Remarks = append(res.Remarks, "SSLv2 not allowed")
			return res, nil
		}

		for _, proto := range cs.Protocols {
			if !contains(allProtos, proto) {
				allProtos = append(allProtos, proto)
			}
		}
	}

	worst := 0
	best := 0
	if contains(allProtos, "TLSv1.2") {
		worst = tlsv12
		best = tlsv12
	}
	if contains(allProtos, "TLSv1.1") {
		if best < tlsv11 {
			best = tlsv11
		}

		if worst > tlsv11 {
			worst = tlsv11
		}
	}
	if contains(allProtos, "TLSv1") {
		if best < tlsv1 {
			best = tlsv1
		}

		if worst > tlsv1 {
			worst = tlsv1
		}
	}
	if contains(allProtos, "SSLv3") {
		if best < sslv3 {
			best = sslv3
		}

		if worst > sslv3 {
			worst = sslv3
		}
	}

	res.Grade = (worst + best) / 2

	return res, nil
}
