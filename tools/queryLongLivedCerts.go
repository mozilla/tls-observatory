// find mozilla certificates that have a ttl longer than 39 months
// Julien Vehent - Apr. 2015
package main

import (
	"encoding/json"
	"fmt"
	elastigo "github.com/mattbaird/elastigo/lib"
	"github.com/mozilla/TLS-Observer/src/certificate"
	"strings"
	"time"
)

func main() {
	es := elastigo.NewConn()
	es.Domain = "localhost:9200"
	step := 0
	seen := make(map[string]bool)
	for {
		filter := fmt.Sprintf(`{"query":{"bool":{"must":[
								{"match": {"validationInfo.Mozilla.isValid": "true"}},
								{"match": {"ca": "false"}}
								]}},
			"from" : %d, "size" : %d}`, step, step+100)
		res, err := es.Search("observer", "certificate", nil, filter)
		if err != nil {
			panic(err)
		}
		if len(res.Hits.Hits) == 0 {
			break
		}
		thirtyNineMonths := time.Duration(28512 * time.Hour)
		for _, storedCert := range res.Hits.Hits {
			cert := new(certificate.Certificate)
			err = json.Unmarshal(*storedCert.Source, cert)
			if err != nil {
				panic(err)
			}
			if _, ok := seen[cert.Hashes.SHA1]; ok {
				// already processed, skip it
				continue
			}
			seen[cert.Hashes.SHA1] = true
			na, err := time.Parse("2006-01-02 15:04:05 +0000 UTC", cert.Validity.NotAfter)
			if err != nil {
				panic(err)
			}
			nb, err := time.Parse("2006-01-02 15:04:05 +0000 UTC", cert.Validity.NotBefore)
			if err != nil {
				panic(err)
			}
			if na.Sub(nb) > thirtyNineMonths {
				fmt.Printf("%s is valid from %s to %s (%.0f months) for domains %s, %s\n",
					cert.Hashes.SHA1, cert.Validity.NotBefore, cert.Validity.NotAfter,
					na.Sub(nb).Hours()/float64(24*30), cert.Subject.CommonName,
					strings.Join(cert.X509v3Extensions.SubjectAlternativeName, ", "))
			}
		}
		step += 100
	}
}

//filter := `{
//	"filter": {
//	    "bool": {
//		"must": [
//		    {
//			"query": {
//			    "match": {
//				"subject.cn": {
//				    "operator": "or",
//				    "query": "mozilla",
//				    "type": "phrase"
//				}
//			    }
//			}
//		    },
//		    {
//			"query": {
//			    "match": {
//				"x509v3Extensions.subjectAlternativeName": {
//				    "operator": "or",
//				    "query": "mozilla",
//				    "type": "phrase"
//				}
//			    }
//			}
//		    }
//		]
//	    }
//	},
//	"query": {
//	    "constant_score": {
//		"query": {
//		    "match_all": {}
//		}
//	    }
//	}
//}`
