package mozillaGradingWorker

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/mozilla/tls-observatory/connection"
)

type testSubject struct {
	name          string
	ciphersuite   string
	expectedScore float64
}

var subjects []testSubject

func init() {
	subjects = append(subjects,
		testSubject{
			name: "pokeinthe.io",
			ciphersuite: pokeinthe,
			expectedScore: float64(94.5),
		},
		testSubject{
			name: "google.com",
			ciphersuite: google,
			expectedScore: float64(91.5),
		},
		testSubject{
			name: "mozilla.org",
			ciphersuite: mozilla,
			expectedScore: float64(87),
		},
	)
}

func TestLevels(t *testing.T) {
	var c connection.Stored

	for _, s := range subjects {
		err := json.Unmarshal([]byte(s.ciphersuite), &c)
		if err != nil {
			t.Error(err)
			t.Error(s.name)
			t.Fail()
		}

		data, err := Evaluate(c)
		if err != nil {
			t.Error(err)
			t.Error(s.name)
			t.Fail()
		}

		res := EvaluationResults{}

		json.Unmarshal(data, &res)

		if res.Grade != s.expectedScore {
			t.Error(s.name)
			t.Error(fmt.Printf("Expected %f and got %f", s.expectedScore, res.Grade))
			t.Fail()
		}
	}
}

var pokeinthe = `{
        "ciphersuite": [
            {
                "cipher": "ECDHE-ECDSA-AES256-GCM-SHA384",
                "curves": [
                    "secp384r1"
                ],
                "ocsp_stapling": true,
                "pfs": "ECDH,P-384,384bits",
                "protocols": [
                    "TLSv1.2"
                ],
                "pubkey": 384,
                "sigalg": "sha256WithRSAEncryption",
                "ticket_hint": "None"
            },
            {
                "cipher": "ECDHE-ECDSA-AES128-GCM-SHA256",
                "curves": [
                    "secp384r1"
                ],
                "ocsp_stapling": true,
                "pfs": "ECDH,P-384,384bits",
                "protocols": [
                    "TLSv1.2"
                ],
                "pubkey": 384,
                "sigalg": "sha256WithRSAEncryption",
                "ticket_hint": "None"
            },
            {
                "cipher": "ECDHE-ECDSA-AES256-SHA384",
                "curves": [
                    "secp384r1"
                ],
                "ocsp_stapling": true,
                "pfs": "ECDH,P-384,384bits",
                "protocols": [
                    "TLSv1.2"
                ],
                "pubkey": 384,
                "sigalg": "sha256WithRSAEncryption",
                "ticket_hint": "None"
            },
            {
                "cipher": "ECDHE-ECDSA-AES128-SHA256",
                "curves": [
                    "secp384r1"
                ],
                "ocsp_stapling": true,
                "pfs": "ECDH,P-384,384bits",
                "protocols": [
                    "TLSv1.2"
                ],
                "pubkey": 384,
                "sigalg": "sha256WithRSAEncryption",
                "ticket_hint": "None"
            },
            {
                "cipher": "ECDHE-ECDSA-AES256-SHA",
                "curves": [
                    "secp384r1"
                ],
                "ocsp_stapling": true,
                "pfs": "ECDH,P-384,384bits",
                "protocols": [
                    "TLSv1",
                    "TLSv1.1",
                    "TLSv1.2"
                ],
                "pubkey": 384,
                "sigalg": "sha256WithRSAEncryption",
                "ticket_hint": "None"
            },
            {
                "cipher": "ECDHE-ECDSA-AES128-SHA",
                "curves": [
                    "secp384r1"
                ],
                "ocsp_stapling": true,
                "pfs": "ECDH,P-384,384bits",
                "protocols": [
                    "TLSv1",
                    "TLSv1.1",
                    "TLSv1.2"
                ],
                "pubkey": 384,
                "sigalg": "sha256WithRSAEncryption",
                "ticket_hint": "None"
            }
        ],
        "scanIP": "45.55.203.36",
        "serverside": true
    }`

var mozilla = `{

    "scanIP": "63.245.215.20",
    "serverside": true,
    "ciphersuite": [
        {
            "cipher": "ECDHE-RSA-AES128-GCM-SHA256",
            "protocols": [
                "TLSv1.2"
            ],
            "pubkey": 2048,
            "sigalg": "sha1WithRSAEncryption",
            "ticket_hint": "None",
            "ocsp_stapling": true,
            "pfs": "ECDH,P-256,256bits",
            "curves": [
                "prime256v1",
                "secp384r1",
                "secp521r1"
            ]
        },
        {
            "cipher": "ECDHE-RSA-AES256-GCM-SHA384",
            "protocols": [
                "TLSv1.2"
            ],
            "pubkey": 2048,
            "sigalg": "sha1WithRSAEncryption",
            "ticket_hint": "None",
            "ocsp_stapling": true,
            "pfs": "ECDH,P-256,256bits",
            "curves": [
                "prime256v1",
                "secp384r1",
                "secp521r1"
            ]
        },
        {
            "cipher": "ECDHE-RSA-AES128-SHA256",
            "protocols": [
                "TLSv1.2"
            ],
            "pubkey": 2048,
            "sigalg": "sha1WithRSAEncryption",
            "ticket_hint": "None",
            "ocsp_stapling": true,
            "pfs": "ECDH,P-256,256bits",
            "curves": [
                "prime256v1",
                "secp384r1",
                "secp521r1"
            ]
        },
        {
            "cipher": "ECDHE-RSA-AES256-SHA384",
            "protocols": [
                "TLSv1.2"
            ],
            "pubkey": 2048,
            "sigalg": "sha1WithRSAEncryption",
            "ticket_hint": "None",
            "ocsp_stapling": true,
            "pfs": "ECDH,P-256,256bits",
            "curves": [
                "prime256v1",
                "secp384r1",
                "secp521r1"
            ]
        },
        {
            "cipher": "ECDHE-RSA-AES128-SHA",
            "protocols": [
                "TLSv1",
                "TLSv1.1",
                "TLSv1.2"
            ],
            "pubkey": 2048,
            "sigalg": "sha1WithRSAEncryption",
            "ticket_hint": "None",
            "ocsp_stapling": true,
            "pfs": "ECDH,P-256,256bits",
            "curves": [
                "prime256v1",
                "secp384r1",
                "secp521r1"
            ]
        },
        {
            "cipher": "ECDHE-RSA-AES256-SHA",
            "protocols": [
                "TLSv1",
                "TLSv1.1",
                "TLSv1.2"
            ],
            "pubkey": 2048,
            "sigalg": "sha1WithRSAEncryption",
            "ticket_hint": "None",
            "ocsp_stapling": true,
            "pfs": "ECDH,P-256,256bits",
            "curves": [
                "prime256v1",
                "secp384r1",
                "secp521r1"
            ]
        },
        {
            "cipher": "DHE-RSA-AES128-GCM-SHA256",
            "protocols": [
                "TLSv1.2"
            ],
            "pubkey": 2048,
            "sigalg": "sha1WithRSAEncryption",
            "ticket_hint": "None",
            "ocsp_stapling": true,
            "pfs": "DH,1024bits"
        },
        {
            "cipher": "DHE-RSA-AES256-GCM-SHA384",
            "protocols": [
                "TLSv1.2"
            ],
            "pubkey": 2048,
            "sigalg": "sha1WithRSAEncryption",
            "ticket_hint": "None",
            "ocsp_stapling": true,
            "pfs": "DH,1024bits"
        },
        {
            "cipher": "DHE-RSA-AES128-SHA256",
            "protocols": [
                "TLSv1.2"
            ],
            "pubkey": 2048,
            "sigalg": "sha1WithRSAEncryption",
            "ticket_hint": "None",
            "ocsp_stapling": true,
            "pfs": "DH,1024bits"
        },
        {
            "cipher": "DHE-RSA-AES256-SHA256",
            "protocols": [
                "TLSv1.2"
            ],
            "pubkey": 2048,
            "sigalg": "sha1WithRSAEncryption",
            "ticket_hint": "None",
            "ocsp_stapling": true,
            "pfs": "DH,1024bits"
        },
        {
            "cipher": "EDH-RSA-DES-CBC3-SHA",
            "protocols": [
                "SSLv3",
                "TLSv1",
                "TLSv1.1",
                "TLSv1.2"
            ],
            "pubkey": 2048,
            "sigalg": "sha1WithRSAEncryption",
            "ticket_hint": "None",
            "ocsp_stapling": true,
            "pfs": "DH,1024bits"
        },
        {
            "cipher": "AES128-GCM-SHA256",
            "protocols": [
                "TLSv1.2"
            ],
            "pubkey": 2048,
            "sigalg": "sha1WithRSAEncryption",
            "ticket_hint": "None",
            "ocsp_stapling": true,
            "pfs": "None"
        },
        {
            "cipher": "AES256-GCM-SHA384",
            "protocols": [
                "TLSv1.2"
            ],
            "pubkey": 2048,
            "sigalg": "sha1WithRSAEncryption",
            "ticket_hint": "None",
            "ocsp_stapling": true,
            "pfs": "None"
        },
        {
            "cipher": "AES128-SHA256",
            "protocols": [
                "TLSv1.2"
            ],
            "pubkey": 2048,
            "sigalg": "sha1WithRSAEncryption",
            "ticket_hint": "None",
            "ocsp_stapling": true,
            "pfs": "None"
        },
        {
            "cipher": "AES256-SHA256",
            "protocols": [
                "TLSv1.2"
            ],
            "pubkey": 2048,
            "sigalg": "sha1WithRSAEncryption",
            "ticket_hint": "None",
            "ocsp_stapling": true,
            "pfs": "None"
        },
        {
            "cipher": "DES-CBC3-SHA",
            "protocols": [
                "SSLv3",
                "TLSv1",
                "TLSv1.1",
                "TLSv1.2"
            ],
            "pubkey": 2048,
            "sigalg": "sha1WithRSAEncryption",
            "ticket_hint": "None",
            "ocsp_stapling": true,
            "pfs": "None"
        }
    ]
}`

var google = `{

    "scanIP": "216.58.195.142",
    "serverside": true,
    "ciphersuite": [
        {
            "cipher": "ECDHE-RSA-CHACHA20-POLY1305",
            "protocols": [
                "TLSv1.2"
            ],
            "pubkey": 2048,
            "sigalg": "sha256WithRSAEncryption",
            "ticket_hint": "100800",
            "pfs": "ECDH,P-256,256bits",
            "curves": [
                "prime256v1"
            ]
        },
        {
            "cipher": "ECDHE-RSA-AES128-GCM-SHA256",
            "protocols": [
                "TLSv1.2"
            ],
            "pubkey": 2048,
            "sigalg": "sha256WithRSAEncryption",
            "ticket_hint": "100800",
            "pfs": "ECDH,P-256,256bits",
            "curves": [
                "prime256v1"
            ]
        },
        {
            "cipher": "ECDHE-RSA-AES128-SHA",
            "protocols": [
                "TLSv1",
                "TLSv1.1",
                "TLSv1.2"
            ],
            "pubkey": 2048,
            "sigalg": "sha256WithRSAEncryption",
            "ticket_hint": "100800",
            "pfs": "ECDH,P-256,256bits",
            "curves": [
                "prime256v1"
            ]
        },
        {
            "cipher": "AES128-GCM-SHA256",
            "protocols": [
                "TLSv1.2"
            ],
            "pubkey": 2048,
            "sigalg": "sha256WithRSAEncryption",
            "ticket_hint": "100800",
            "pfs": "None"
        },
        {
            "cipher": "AES128-SHA",
            "protocols": [
                "TLSv1",
                "TLSv1.1",
                "TLSv1.2"
            ],
            "pubkey": 2048,
            "sigalg": "sha256WithRSAEncryption",
            "ticket_hint": "100800",
            "pfs": "None"
        },
        {
            "cipher": "AES128-SHA256",
            "protocols": [
                "TLSv1.2"
            ],
            "pubkey": 2048,
            "sigalg": "sha256WithRSAEncryption",
            "ticket_hint": "100800",
            "pfs": "None"
        },
        {
            "cipher": "DES-CBC3-SHA",
            "protocols": [
                "TLSv1",
                "TLSv1.1",
                "TLSv1.2"
            ],
            "pubkey": 2048,
            "sigalg": "sha256WithRSAEncryption",
            "ticket_hint": "100800",
            "pfs": "None"
        },
        {
            "cipher": "ECDHE-RSA-AES256-GCM-SHA384",
            "protocols": [
                "TLSv1.2"
            ],
            "pubkey": 2048,
            "sigalg": "sha256WithRSAEncryption",
            "ticket_hint": "100800",
            "pfs": "ECDH,P-256,256bits",
            "curves": [
                "prime256v1"
            ]
        },
        {
            "cipher": "ECDHE-RSA-AES128-SHA256",
            "protocols": [
                "TLSv1.2"
            ],
            "pubkey": 2048,
            "sigalg": "sha256WithRSAEncryption",
            "ticket_hint": "100800",
            "pfs": "ECDH,P-256,256bits",
            "curves": [
                "prime256v1"
            ]
        },
        {
            "cipher": "ECDHE-RSA-AES256-SHA",
            "protocols": [
                "TLSv1",
                "TLSv1.1",
                "TLSv1.2"
            ],
            "pubkey": 2048,
            "sigalg": "sha256WithRSAEncryption",
            "ticket_hint": "100800",
            "pfs": "ECDH,P-256,256bits",
            "curves": [
                "prime256v1"
            ]
        },
        {
            "cipher": "ECDHE-RSA-AES256-SHA384",
            "protocols": [
                "TLSv1.2"
            ],
            "pubkey": 2048,
            "sigalg": "sha256WithRSAEncryption",
            "ticket_hint": "100800",
            "pfs": "ECDH,P-256,256bits",
            "curves": [
                "prime256v1"
            ]
        },
        {
            "cipher": "AES256-GCM-SHA384",
            "protocols": [
                "TLSv1.2"
            ],
            "pubkey": 2048,
            "sigalg": "sha256WithRSAEncryption",
            "ticket_hint": "100800",
            "pfs": "None"
        },
        {
            "cipher": "AES256-SHA",
            "protocols": [
                "TLSv1",
                "TLSv1.1",
                "TLSv1.2"
            ],
            "pubkey": 2048,
            "sigalg": "sha256WithRSAEncryption",
            "ticket_hint": "100800",
            "pfs": "None"
        },
        {
            "cipher": "AES256-SHA256",
            "protocols": [
                "TLSv1.2"
            ],
            "pubkey": 2048,
            "sigalg": "sha256WithRSAEncryption",
            "ticket_hint": "100800",
            "pfs": "None"
        }
    ]

}`
