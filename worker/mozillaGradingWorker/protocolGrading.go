package mozillaGradingWorker

import "github.com/mozilla/tls-observatory/connection"

const (
	SSLv2  = 0
	SSLv3  = 80
	TLSv1  = 90
	TLSv11 = 95
	TLSv12 = 100
)

func gradeProtocol(connInfo connection.Stored) (categoryResults, error) {

	res := categoryResults{}
	var allProtos []string
	for _, cs := range connInfo.CipherSuite {

		if contains(cs.Protocols, "SSLv2") {
			res.Grade = 0
			res.Fail = true
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
		worst = TLSv12
		best = TLSv12
	}
	if contains(allProtos, "TLSv1.1") {
		if best < TLSv11 {
			best = TLSv11
		}

		if worst > TLSv11 {
			worst = TLSv11
		}
	}
	if contains(allProtos, "TLSv1") {
		if best < TLSv1 {
			best = TLSv1
		}

		if worst > TLSv1 {
			worst = TLSv1
		}
	}
	if contains(allProtos, "SSLv3") {
		if best < SSLv3 {
			best = SSLv3
		}

		if worst > SSLv3 {
			worst = SSLv3
		}
	}

	res.Grade = (worst + best) / 2

	return res, nil
}
