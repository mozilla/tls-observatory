package mozillaEvaluationWorker

import (
	"encoding/json"
	"testing"

	"github.com/mozilla/tls-observatory/connection"
)

type testParams struct {
	expectedLevel    string
	expectedFailures []string
	cipherscan       string
	certSignature    string
}

func TestLevels(t *testing.T) {
	var tps = []testParams{
		{
			expectedLevel: "modern",
			cipherscan:    `{"scanIP":"62.210.76.92","serverside":true,"ciphersuite":[{"cipher":"ECDHE-RSA-AES128-GCM-SHA256","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","ocsp_stapling":true,"pfs":"ECDH,P-384,384bits","curves":["secp384r1"]},{"cipher":"ECDHE-RSA-AES256-GCM-SHA384","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","ocsp_stapling":true,"pfs":"ECDH,P-384,384bits","curves":["secp384r1"]},{"cipher":"ECDHE-RSA-AES128-SHA256","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","ocsp_stapling":true,"pfs":"ECDH,P-384,384bits","curves":["secp384r1"]},{"cipher":"ECDHE-RSA-AES256-SHA384","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","ocsp_stapling":true,"pfs":"ECDH,P-384,384bits","curves":["secp384r1"]}]}`,
			certSignature: "ECDSAWithSHA384",
		},
		{
			expectedLevel: "intermediate",
			cipherscan:    `{"scanIP":"52.27.175.225","serverside":true,"ciphersuite":[{"cipher":"ECDHE-RSA-AES128-GCM-SHA256","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","pfs":"ECDH,P-256,256bits","curves":["prime256v1"]},{"cipher":"ECDHE-RSA-AES128-SHA256","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","pfs":"ECDH,P-256,256bits","curves":["prime256v1"]},{"cipher":"ECDHE-RSA-AES128-SHA","protocols":["TLSv1","TLSv1.1","TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","pfs":"ECDH,P-256,256bits","curves":["prime256v1"]},{"cipher":"DHE-RSA-AES128-SHA","protocols":["TLSv1","TLSv1.1","TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","pfs":"DH,2048bits"},{"cipher":"ECDHE-RSA-AES256-GCM-SHA384","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","pfs":"ECDH,P-256,256bits","curves":["prime256v1"]},{"cipher":"ECDHE-RSA-AES256-SHA384","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","pfs":"ECDH,P-256,256bits","curves":["prime256v1"]},{"cipher":"ECDHE-RSA-AES256-SHA","protocols":["TLSv1","TLSv1.1","TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","pfs":"ECDH,P-256,256bits","curves":["prime256v1"]},{"cipher":"AES128-GCM-SHA256","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","pfs":"None"},{"cipher":"AES128-SHA256","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","pfs":"None"},{"cipher":"AES128-SHA","protocols":["TLSv1","TLSv1.1","TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","pfs":"None"},{"cipher":"AES256-GCM-SHA384","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","pfs":"None"},{"cipher":"AES256-SHA256","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","pfs":"None"},{"cipher":"AES256-SHA","protocols":["TLSv1","TLSv1.1","TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","pfs":"None"},{"cipher":"DES-CBC3-SHA","protocols":["TLSv1","TLSv1.1","TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","pfs":"None"}]}`,
			certSignature: "SHA256WithRSA",
		},
		{
			expectedLevel: "old",
			cipherscan:    `{"scanIP":"63.245.215.20","serverside":true,"ciphersuite":[{"cipher":"ECDHE-RSA-AES128-GCM-SHA256","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha1WithRSAEncryption","ticket_hint":"None","ocsp_stapling":true,"pfs":"ECDH,P-256,256bits","curves":["prime256v1","secp384r1","secp521r1"]},{"cipher":"ECDHE-RSA-AES256-GCM-SHA384","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha1WithRSAEncryption","ticket_hint":"None","ocsp_stapling":true,"pfs":"ECDH,P-256,256bits","curves":["prime256v1","secp384r1","secp521r1"]},{"cipher":"ECDHE-RSA-AES128-SHA256","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha1WithRSAEncryption","ticket_hint":"None","ocsp_stapling":true,"pfs":"ECDH,P-256,256bits","curves":["prime256v1","secp384r1","secp521r1"]},{"cipher":"ECDHE-RSA-AES256-SHA384","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha1WithRSAEncryption","ticket_hint":"None","ocsp_stapling":true,"pfs":"ECDH,P-256,256bits","curves":["prime256v1","secp384r1","secp521r1"]},{"cipher":"ECDHE-RSA-AES128-SHA","protocols":["TLSv1","TLSv1.1","TLSv1.2"],"pubkey":2048,"sigalg":"sha1WithRSAEncryption","ticket_hint":"None","ocsp_stapling":true,"pfs":"ECDH,P-256,256bits","curves":["prime256v1","secp384r1","secp521r1"]},{"cipher":"ECDHE-RSA-AES256-SHA","protocols":["TLSv1","TLSv1.1","TLSv1.2"],"pubkey":2048,"sigalg":"sha1WithRSAEncryption","ticket_hint":"None","ocsp_stapling":true,"pfs":"ECDH,P-256,256bits","curves":["prime256v1","secp384r1","secp521r1"]},{"cipher":"DHE-RSA-AES128-GCM-SHA256","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha1WithRSAEncryption","ticket_hint":"None","ocsp_stapling":true,"pfs":"DH,1024bits"},{"cipher":"DHE-RSA-AES256-GCM-SHA384","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha1WithRSAEncryption","ticket_hint":"None","ocsp_stapling":true,"pfs":"DH,1024bits"},{"cipher":"DHE-RSA-AES128-SHA256","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha1WithRSAEncryption","ticket_hint":"None","ocsp_stapling":true,"pfs":"DH,1024bits"},{"cipher":"DHE-RSA-AES256-SHA256","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha1WithRSAEncryption","ticket_hint":"None","ocsp_stapling":true,"pfs":"DH,1024bits"},{"cipher":"AES128-GCM-SHA256","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha1WithRSAEncryption","ticket_hint":"None","ocsp_stapling":true,"pfs":"None"},{"cipher":"AES256-GCM-SHA384","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha1WithRSAEncryption","ticket_hint":"None","ocsp_stapling":true,"pfs":"None"},{"cipher":"AES128-SHA256","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha1WithRSAEncryption","ticket_hint":"None","ocsp_stapling":true,"pfs":"None"},{"cipher":"AES256-SHA256","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha1WithRSAEncryption","ticket_hint":"None","ocsp_stapling":true,"pfs":"None"},{"cipher":"DES-CBC3-SHA","protocols":["SSLv3","TLSv1","TLSv1.1","TLSv1.2"],"pubkey":2048,"sigalg":"sha1WithRSAEncryption","ticket_hint":"None","ocsp_stapling":true,"pfs":"None"}]}`,
			certSignature: "SHA1WithRSA",
		},
		{
			expectedLevel: "bad",
			cipherscan:    `{"scanIP":"62.210.76.92","serverside":true,"ciphersuite":[{"cipher":"RC4-MD5","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","ocsp_stapling":true,"pfs":"ECDH,P-384,384bits","curves":["secp384r1"]},{"cipher":"ECDHE-RSA-AES256-GCM-SHA384","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","ocsp_stapling":true,"pfs":"ECDH,P-384,384bits","curves":["secp384r1"]},{"cipher":"ECDHE-RSA-AES128-SHA256","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","ocsp_stapling":true,"pfs":"ECDH,P-384,384bits","curves":["secp384r1"]},{"cipher":"ECDHE-RSA-AES256-SHA384","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","ocsp_stapling":true,"pfs":"ECDH,P-384,384bits","curves":["secp384r1"]}]}`,
			certSignature: "MD5WithRSA",
		},
	}
	for _, tp := range tps {
		var info connection.Stored
		err := json.Unmarshal([]byte(tp.cipherscan), &info)
		if err != nil {
			t.Error("Failed to unmarshal test suite")
			t.Error(err)
			t.Fail()
		}
		out, err := Evaluate(info, tp.certSignature)
		if err != nil {
			t.Error("Could not evaluate cipherscan output.")
			t.Error(err)
			t.Fail()
		}
		var results EvaluationResults
		err = json.Unmarshal(out, &results)
		if err != nil {
			t.Error("Could not unmarshal results from json")
			t.Error(err)
			t.Fail()
		}
		if results.Level != tp.expectedLevel {
			t.Error("Measured level", results.Level, "does not match expected of", tp.expectedLevel)
			t.Logf("%v+", results)
			t.Fail()
		}
	}
}

func TestOrderings(t *testing.T) {
	var tps = []testParams{
		{
			expectedLevel:    "modern",
			expectedFailures: []string{`considering fixing ciphers ordering`},
			cipherscan:       `{"scanIP":"62.210.76.92","serverside":true,"ciphersuite":[{"cipher":"ECDHE-RSA-AES128-GCM-SHA256","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","ocsp_stapling":true,"pfs":"ECDH,P-384,384bits","curves":["secp384r1"]},{"cipher":"ECDHE-RSA-AES256-GCM-SHA384","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","ocsp_stapling":true,"pfs":"ECDH,P-384,384bits","curves":["secp384r1"]}]}`,
			certSignature:    "ECDSAWithSHA384",
		},
		{
			expectedLevel:    "modern",
			expectedFailures: []string{`enable Perfect Forward Secrecy with a curve of at least 384bits, don't use DHE`, `remove cipher DHE-RSA-AES128-GCM-SHA256`},
			cipherscan:       `{"scanIP":"62.210.76.92","serverside":true,"ciphersuite":[{"cipher":"ECDHE-RSA-AES128-GCM-SHA256","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","ocsp_stapling":true,"pfs":"ECDH,P-384,384bits","curves":["secp384r1"]},{"cipher":"ECDHE-RSA-AES256-GCM-SHA384","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","ocsp_stapling":true,"pfs":"ECDH,P-384,384bits","curves":["secp384r1"]},{"cipher":"DHE-RSA-AES128-GCM-SHA256","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha1WithRSAEncryption","ticket_hint":"None","ocsp_stapling":true,"pfs":"DH,1024bits"}]}`,
			certSignature:    "ECDSAWithSHA384",
		},
		{
			expectedLevel:    "modern",
			expectedFailures: []string{`sha256WithRSAEncryption is not a modern certificate signature, use ecdsa-with-SHA384`},
			cipherscan:       `{"scanIP":"62.210.76.92","serverside":true,"ciphersuite":[{"cipher":"ECDHE-RSA-AES128-GCM-SHA256","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","ocsp_stapling":true,"pfs":"ECDH,P-384,384bits","curves":["secp384r1"]},{"cipher":"ECDHE-RSA-AES256-GCM-SHA384","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","ocsp_stapling":true,"pfs":"ECDH,P-384,384bits","curves":["secp384r1"]}]}`,
			certSignature:    "SHA256WithRSA",
		},
		{
			expectedLevel:    "intermediate",
			expectedFailures: []string{`sha1WithRSAEncryption is not an intermediate certificate signature, use sha256WithRSAEncryption`},
			cipherscan:       `{"scanIP":"62.210.76.92","serverside":true,"ciphersuite":[{"cipher":"ECDHE-RSA-AES128-GCM-SHA256","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","ocsp_stapling":true,"pfs":"ECDH,P-384,384bits","curves":["secp384r1"]},{"cipher":"ECDHE-RSA-AES256-GCM-SHA384","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","ocsp_stapling":true,"pfs":"ECDH,P-384,384bits","curves":["secp384r1"]}]}`,
			certSignature:    "SHA1WithRSA",
		},
	}
	for _, tp := range tps {
		var info connection.Stored
		err := json.Unmarshal([]byte(tp.cipherscan), &info)
		if err != nil {
			t.Error("Failed to unmarshal test suite")
			t.Error(err)
			t.Fail()
		}
		out, err := Evaluate(info, tp.certSignature)
		if err != nil {
			t.Error("Could not evaluate cipherscan output.")
			t.Error(err)
			t.Fail()
		}
		var results EvaluationResults
		err = json.Unmarshal(out, &results)
		if err != nil {
			t.Error("Could not unmarshal results from json")
			t.Error(err)
			t.Fail()
		}
		for _, ef := range tp.expectedFailures {
			if !contains(results.Failures[tp.expectedLevel], ef) {
				t.Errorf("Expected failure %q not found in results", ef)
				t.Logf("%v+", results.Failures[tp.expectedLevel])
				t.Fail()
			}
		}
	}
}
