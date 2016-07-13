package mozillaGradingWorker

import (
	"encoding/json"
	"testing"

	"github.com/mozilla/tls-observatory/connection"
)

var conn = `{
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

func TestLevels(t *testing.T) {
	var c connection.Stored

	err := json.Unmarshal([]byte(conn), &c)
	if err != nil {
		return
	}

	Evaluate(c)
}
