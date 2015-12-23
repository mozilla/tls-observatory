package mozillaEvaluationWorker

import (
	"encoding/json"
	"testing"

	"github.com/mozilla/tls-observatory/certificate"
	"github.com/mozilla/tls-observatory/connection"
)

type testParams struct {
	expectedLevel    string
	expectedFailures []string
	cipherscan       string
	certificate      string
}

func TestLevels(t *testing.T) {
	var tps = []testParams{
		{
			expectedLevel: "modern",
			cipherscan:    `{"scanIP":"62.210.76.92","serverside":true,"ciphersuite":[{"cipher":"ECDHE-RSA-AES128-GCM-SHA256","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","ocsp_stapling":true,"pfs":"ECDH,P-384,384bits","curves":["secp384r1"]},{"cipher":"ECDHE-RSA-AES256-GCM-SHA384","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","ocsp_stapling":true,"pfs":"ECDH,P-384,384bits","curves":["secp384r1"]},{"cipher":"ECDHE-RSA-AES128-SHA256","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","ocsp_stapling":true,"pfs":"ECDH,P-384,384bits","curves":["secp384r1"]},{"cipher":"ECDHE-RSA-AES256-SHA384","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","ocsp_stapling":true,"pfs":"ECDH,P-384,384bits","curves":["secp384r1"]}]}`,
			certificate:   `{"version":3,"signatureAlgorithm":"SHA256WithRSA","issuer":{"c":["US"],"o":["Google Inc"],"cn":"Google Internet Authority G2"},"validity":{"notBefore":"2015-11-26T00:09:43Z","notAfter":"2016-02-23T00:00:00Z"},"subject":{"c":["US"],"o":["Google Inc"],"cn":"*.google.com"},"subjectPublicKeyInfo":{"publicKeyAlgorithm":"ECDSA"},"x509v3Extensions":{"authorityKeyId":"St0GFhu89mi1dvWBtrtiGrpagS8=","subjectKeyId":"anFuWi3mReGqQcviW7pN+UpNuTQ=","keyUsage":["Digital Signature"],"extendedKeyUsage":["ExtKeyUsageServerAuth","ExtKeyUsageClientAuth"],"subjectAlternativeName":["*.google.com","*.android.com"],"crlDistributionPoint":["http://pki.google.com/GIAG2.crl"]},"x509v3BasicConstraints":"Critical","validationInfo":{"Android":{"isValid":true},"Apple":{"isValid":true},"Microsoft":{"isValid":true},"Mozilla":{"isValid":true},"Ubuntu":{"isValid":true}},"firstSeenTimestamp":"2015-12-03T20:29:14.540124Z","lastSeenTimestamp":"2015-12-05T14:18:27.723626Z","hashes":{"sha1":"72F15B6AA9A6DE87C098FE7662058D3EE0AA97BF","sha256":"E75D8D87D1712FBAACF0B9CDEC80C3AAEAB659A2D658917BB1402FA5A56DC5BB"},"Raw":""}`,
		},
		{
			expectedLevel: "intermediate",
			cipherscan:    `{"scanIP":"52.27.175.225","serverside":true,"ciphersuite":[{"cipher":"ECDHE-RSA-AES128-GCM-SHA256","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","pfs":"ECDH,P-256,256bits","curves":["prime256v1"]},{"cipher":"ECDHE-RSA-AES128-SHA256","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","pfs":"ECDH,P-256,256bits","curves":["prime256v1"]},{"cipher":"ECDHE-RSA-AES128-SHA","protocols":["TLSv1","TLSv1.1","TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","pfs":"ECDH,P-256,256bits","curves":["prime256v1"]},{"cipher":"DHE-RSA-AES128-SHA","protocols":["TLSv1","TLSv1.1","TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","pfs":"DH,2048bits"},{"cipher":"ECDHE-RSA-AES256-GCM-SHA384","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","pfs":"ECDH,P-256,256bits","curves":["prime256v1"]},{"cipher":"ECDHE-RSA-AES256-SHA384","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","pfs":"ECDH,P-256,256bits","curves":["prime256v1"]},{"cipher":"ECDHE-RSA-AES256-SHA","protocols":["TLSv1","TLSv1.1","TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","pfs":"ECDH,P-256,256bits","curves":["prime256v1"]},{"cipher":"AES128-GCM-SHA256","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","pfs":"None"},{"cipher":"AES128-SHA256","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","pfs":"None"},{"cipher":"AES128-SHA","protocols":["TLSv1","TLSv1.1","TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","pfs":"None"},{"cipher":"AES256-GCM-SHA384","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","pfs":"None"},{"cipher":"AES256-SHA256","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","pfs":"None"},{"cipher":"AES256-SHA","protocols":["TLSv1","TLSv1.1","TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","pfs":"None"},{"cipher":"DES-CBC3-SHA","protocols":["TLSv1","TLSv1.1","TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","pfs":"None"}]}`,
			certificate:   `{"version":3,"signatureAlgorithm":"SHA256WithRSA","issuer":{"c":["US"],"o":["Google Inc"],"cn":"Google Internet Authority G2"},"validity":{"notBefore":"2015-11-26T00:09:43Z","notAfter":"2016-02-23T00:00:00Z"},"subject":{"c":["US"],"o":["Google Inc"],"cn":"*.google.com"},"subjectPublicKeyInfo":{"publicKeyAlgorithm":"RSA"},"x509v3Extensions":{"authorityKeyId":"St0GFhu89mi1dvWBtrtiGrpagS8=","subjectKeyId":"anFuWi3mReGqQcviW7pN+UpNuTQ=","keyUsage":["Digital Signature"],"extendedKeyUsage":["ExtKeyUsageServerAuth","ExtKeyUsageClientAuth"],"subjectAlternativeName":["*.google.com","*.android.com"],"crlDistributionPoint":["http://pki.google.com/GIAG2.crl"]},"x509v3BasicConstraints":"Critical","validationInfo":{"Android":{"isValid":true},"Apple":{"isValid":true},"Microsoft":{"isValid":true},"Mozilla":{"isValid":true},"Ubuntu":{"isValid":true}},"firstSeenTimestamp":"2015-12-03T20:29:14.540124Z","lastSeenTimestamp":"2015-12-05T14:18:27.723626Z","hashes":{"sha1":"72F15B6AA9A6DE87C098FE7662058D3EE0AA97BF","sha256":"E75D8D87D1712FBAACF0B9CDEC80C3AAEAB659A2D658917BB1402FA5A56DC5BB"},"Raw":""}`,
		},
		{
			expectedLevel: "old",
			cipherscan:    `{"scanIP":"63.245.215.20","serverside":true,"ciphersuite":[{"cipher":"ECDHE-RSA-AES128-GCM-SHA256","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha1WithRSAEncryption","ticket_hint":"None","ocsp_stapling":true,"pfs":"ECDH,P-256,256bits","curves":["prime256v1","secp384r1","secp521r1"]},{"cipher":"ECDHE-RSA-AES256-GCM-SHA384","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha1WithRSAEncryption","ticket_hint":"None","ocsp_stapling":true,"pfs":"ECDH,P-256,256bits","curves":["prime256v1","secp384r1","secp521r1"]},{"cipher":"ECDHE-RSA-AES128-SHA256","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha1WithRSAEncryption","ticket_hint":"None","ocsp_stapling":true,"pfs":"ECDH,P-256,256bits","curves":["prime256v1","secp384r1","secp521r1"]},{"cipher":"ECDHE-RSA-AES256-SHA384","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha1WithRSAEncryption","ticket_hint":"None","ocsp_stapling":true,"pfs":"ECDH,P-256,256bits","curves":["prime256v1","secp384r1","secp521r1"]},{"cipher":"ECDHE-RSA-AES128-SHA","protocols":["TLSv1","TLSv1.1","TLSv1.2"],"pubkey":2048,"sigalg":"sha1WithRSAEncryption","ticket_hint":"None","ocsp_stapling":true,"pfs":"ECDH,P-256,256bits","curves":["prime256v1","secp384r1","secp521r1"]},{"cipher":"ECDHE-RSA-AES256-SHA","protocols":["TLSv1","TLSv1.1","TLSv1.2"],"pubkey":2048,"sigalg":"sha1WithRSAEncryption","ticket_hint":"None","ocsp_stapling":true,"pfs":"ECDH,P-256,256bits","curves":["prime256v1","secp384r1","secp521r1"]},{"cipher":"DHE-RSA-AES128-GCM-SHA256","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha1WithRSAEncryption","ticket_hint":"None","ocsp_stapling":true,"pfs":"DH,1024bits"},{"cipher":"DHE-RSA-AES256-GCM-SHA384","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha1WithRSAEncryption","ticket_hint":"None","ocsp_stapling":true,"pfs":"DH,1024bits"},{"cipher":"DHE-RSA-AES128-SHA256","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha1WithRSAEncryption","ticket_hint":"None","ocsp_stapling":true,"pfs":"DH,1024bits"},{"cipher":"DHE-RSA-AES256-SHA256","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha1WithRSAEncryption","ticket_hint":"None","ocsp_stapling":true,"pfs":"DH,1024bits"},{"cipher":"AES128-GCM-SHA256","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha1WithRSAEncryption","ticket_hint":"None","ocsp_stapling":true,"pfs":"None"},{"cipher":"AES256-GCM-SHA384","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha1WithRSAEncryption","ticket_hint":"None","ocsp_stapling":true,"pfs":"None"},{"cipher":"AES128-SHA256","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha1WithRSAEncryption","ticket_hint":"None","ocsp_stapling":true,"pfs":"None"},{"cipher":"AES256-SHA256","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha1WithRSAEncryption","ticket_hint":"None","ocsp_stapling":true,"pfs":"None"},{"cipher":"DES-CBC3-SHA","protocols":["SSLv3","TLSv1","TLSv1.1","TLSv1.2"],"pubkey":2048,"sigalg":"sha1WithRSAEncryption","ticket_hint":"None","ocsp_stapling":true,"pfs":"None"}]}`,
			certificate:   `{"version":3,"signatureAlgorithm":"SHA1WithRSA","issuer":{"c":["US"],"o":["Google Inc"],"cn":"Google Internet Authority G2"},"validity":{"notBefore":"2015-11-26T00:09:43Z","notAfter":"2016-02-23T00:00:00Z"},"subject":{"c":["US"],"o":["Google Inc"],"cn":"*.google.com"},"subjectPublicKeyInfo":{"publicKeyAlgorithm":"RSA"},"x509v3Extensions":{"authorityKeyId":"St0GFhu89mi1dvWBtrtiGrpagS8=","subjectKeyId":"anFuWi3mReGqQcviW7pN+UpNuTQ=","keyUsage":["Digital Signature"],"extendedKeyUsage":["ExtKeyUsageServerAuth","ExtKeyUsageClientAuth"],"subjectAlternativeName":["*.google.com","*.android.com"],"crlDistributionPoint":["http://pki.google.com/GIAG2.crl"]},"x509v3BasicConstraints":"Critical","validationInfo":{"Android":{"isValid":true},"Apple":{"isValid":true},"Microsoft":{"isValid":true},"Mozilla":{"isValid":true},"Ubuntu":{"isValid":true}},"firstSeenTimestamp":"2015-12-03T20:29:14.540124Z","lastSeenTimestamp":"2015-12-05T14:18:27.723626Z","hashes":{"sha1":"72F15B6AA9A6DE87C098FE7662058D3EE0AA97BF","sha256":"E75D8D87D1712FBAACF0B9CDEC80C3AAEAB659A2D658917BB1402FA5A56DC5BB"},"Raw":""}`,
		},
		{
			expectedLevel: "bad",
			cipherscan:    `{"scanIP":"62.210.76.92","serverside":true,"ciphersuite":[{"cipher":"RC4-MD5","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","ocsp_stapling":true,"pfs":"ECDH,P-384,384bits","curves":["secp384r1"]},{"cipher":"ECDHE-RSA-AES256-GCM-SHA384","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","ocsp_stapling":true,"pfs":"ECDH,P-384,384bits","curves":["secp384r1"]},{"cipher":"ECDHE-RSA-AES128-SHA256","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","ocsp_stapling":true,"pfs":"ECDH,P-384,384bits","curves":["secp384r1"]},{"cipher":"ECDHE-RSA-AES256-SHA384","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","ocsp_stapling":true,"pfs":"ECDH,P-384,384bits","curves":["secp384r1"]}]}`,
			certificate:   `{"version":3,"signatureAlgorithm":"MD5WithRSA","issuer":{"c":["US"],"o":["Google Inc"],"cn":"Google Internet Authority G2"},"validity":{"notBefore":"2015-11-26T00:09:43Z","notAfter":"2016-02-23T00:00:00Z"},"subject":{"c":["US"],"o":["Google Inc"],"cn":"*.google.com"},"subjectPublicKeyInfo":{"publicKeyAlgorithm":"RSA"},"x509v3Extensions":{"authorityKeyId":"St0GFhu89mi1dvWBtrtiGrpagS8=","subjectKeyId":"anFuWi3mReGqQcviW7pN+UpNuTQ=","keyUsage":["Digital Signature"],"extendedKeyUsage":["ExtKeyUsageServerAuth","ExtKeyUsageClientAuth"],"subjectAlternativeName":["*.google.com","*.android.com"],"crlDistributionPoint":["http://pki.google.com/GIAG2.crl"]},"x509v3BasicConstraints":"Critical","validationInfo":{"Android":{"isValid":true},"Apple":{"isValid":true},"Microsoft":{"isValid":true},"Mozilla":{"isValid":true},"Ubuntu":{"isValid":true}},"firstSeenTimestamp":"2015-12-03T20:29:14.540124Z","lastSeenTimestamp":"2015-12-05T14:18:27.723626Z","hashes":{"sha1":"72F15B6AA9A6DE87C098FE7662058D3EE0AA97BF","sha256":"E75D8D87D1712FBAACF0B9CDEC80C3AAEAB659A2D658917BB1402FA5A56DC5BB"},"Raw":""}`,
		},
	}
	for _, tp := range tps {
		var info connection.Stored
		err := json.Unmarshal([]byte(tp.cipherscan), &info)
		if err != nil {
			t.Error("Failed to unmarshal test cipherscan")
			t.Error(err)
			t.Fail()
		}
		var cert certificate.Certificate
		err = json.Unmarshal([]byte(tp.certificate), &cert)
		if err != nil {
			t.Error("Failed to unmarshal test certificate")
			t.Error(err)
			t.Fail()
		}
		out, err := Evaluate(info, cert)
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

func TestFailures(t *testing.T) {
	var tps = []testParams{
		{
			expectedLevel:    "bad",
			expectedFailures: []string{`don't use a public key shorter than 2048bits`},
			cipherscan:       `{"scanIP":"62.210.76.92","serverside":true,"ciphersuite":[{"cipher":"ECDHE-RSA-AES128-GCM-SHA256","protocols":["TLSv1.2"],"pubkey":512,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","ocsp_stapling":true,"pfs":"ECDH,P-384,384bits","curves":["secp384r1"]}]}`,
			certificate:      `{"version":3,"signatureAlgorithm":"MD5WithRSA","issuer":{"c":["US"],"o":["Google Inc"],"cn":"Google Internet Authority G2"},"validity":{"notBefore":"2015-11-26T00:09:43Z","notAfter":"2016-02-23T00:00:00Z"},"subject":{"c":["US"],"o":["Google Inc"],"cn":"*.google.com"},"subjectPublicKeyInfo":{"publicKeyAlgorithm":"RSA"},"x509v3Extensions":{"authorityKeyId":"St0GFhu89mi1dvWBtrtiGrpagS8=","subjectKeyId":"anFuWi3mReGqQcviW7pN+UpNuTQ=","keyUsage":["Digital Signature"],"extendedKeyUsage":["ExtKeyUsageServerAuth","ExtKeyUsageClientAuth"],"subjectAlternativeName":["*.google.com","*.android.com"],"crlDistributionPoint":["http://pki.google.com/GIAG2.crl"]},"x509v3BasicConstraints":"Critical","validationInfo":{"Android":{"isValid":true},"Apple":{"isValid":true},"Microsoft":{"isValid":true},"Mozilla":{"isValid":true},"Ubuntu":{"isValid":true}},"firstSeenTimestamp":"2015-12-03T20:29:14.540124Z","lastSeenTimestamp":"2015-12-05T14:18:27.723626Z","hashes":{"sha1":"72F15B6AA9A6DE87C098FE7662058D3EE0AA97BF","sha256":"E75D8D87D1712FBAACF0B9CDEC80C3AAEAB659A2D658917BB1402FA5A56DC5BB"},"Raw":""}`,
		},
		{
			expectedLevel:    "modern",
			expectedFailures: []string{`fix ciphersuite ordering, use recommended modern ciphersuite`},
			cipherscan:       `{"scanIP":"62.210.76.92","serverside":true,"ciphersuite":[{"cipher":"ECDHE-RSA-AES128-GCM-SHA256","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","ocsp_stapling":true,"pfs":"ECDH,P-384,384bits","curves":["secp384r1"]},{"cipher":"ECDHE-RSA-AES256-GCM-SHA384","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","ocsp_stapling":true,"pfs":"ECDH,P-384,384bits","curves":["secp384r1"]}]}`,
			certificate:      `{"version":3,"signatureAlgorithm":"ECDSAWithSHA256","issuer":{"c":["US"],"o":["Google Inc"],"cn":"Google Internet Authority G2"},"validity":{"notBefore":"2015-11-26T00:09:43Z","notAfter":"2016-02-23T00:00:00Z"},"subject":{"c":["US"],"o":["Google Inc"],"cn":"*.google.com"},"subjectPublicKeyInfo":{"publicKeyAlgorithm":"ECDSA"},"x509v3Extensions":{"authorityKeyId":"St0GFhu89mi1dvWBtrtiGrpagS8=","subjectKeyId":"anFuWi3mReGqQcviW7pN+UpNuTQ=","keyUsage":["Digital Signature"],"extendedKeyUsage":["ExtKeyUsageServerAuth","ExtKeyUsageClientAuth"],"subjectAlternativeName":["*.google.com","*.android.com"],"crlDistributionPoint":["http://pki.google.com/GIAG2.crl"]},"x509v3BasicConstraints":"Critical","validationInfo":{"Android":{"isValid":true},"Apple":{"isValid":true},"Microsoft":{"isValid":true},"Mozilla":{"isValid":true},"Ubuntu":{"isValid":true}},"firstSeenTimestamp":"2015-12-03T20:29:14.540124Z","lastSeenTimestamp":"2015-12-05T14:18:27.723626Z","hashes":{"sha1":"72F15B6AA9A6DE87C098FE7662058D3EE0AA97BF","sha256":"E75D8D87D1712FBAACF0B9CDEC80C3AAEAB659A2D658917BB1402FA5A56DC5BB"},"Raw":""}`,
		},
		{
			expectedLevel:    "modern",
			expectedFailures: []string{`enable Perfect Forward Secrecy with a curve of at least 256bits, don't use DHE`, `remove cipher DHE-RSA-AES128-GCM-SHA256`},
			cipherscan:       `{"scanIP":"62.210.76.92","serverside":true,"ciphersuite":[{"cipher":"ECDHE-RSA-AES128-GCM-SHA256","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","ocsp_stapling":true,"pfs":"ECDH,P-384,384bits","curves":["secp384r1"]},{"cipher":"ECDHE-RSA-AES256-GCM-SHA384","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","ocsp_stapling":true,"pfs":"ECDH,P-384,384bits","curves":["secp384r1"]},{"cipher":"DHE-RSA-AES128-GCM-SHA256","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha1WithRSAEncryption","ticket_hint":"None","ocsp_stapling":true,"pfs":"DH,1024bits"}]}`,
			certificate:      `{"version":3,"signatureAlgorithm":"ECDSAWithSHA256","issuer":{"c":["US"],"o":["Google Inc"],"cn":"Google Internet Authority G2"},"validity":{"notBefore":"2015-11-26T00:09:43Z","notAfter":"2016-02-23T00:00:00Z"},"subject":{"c":["US"],"o":["Google Inc"],"cn":"*.google.com"},"subjectPublicKeyInfo":{"publicKeyAlgorithm":"ECDSA"},"x509v3Extensions":{"authorityKeyId":"St0GFhu89mi1dvWBtrtiGrpagS8=","subjectKeyId":"anFuWi3mReGqQcviW7pN+UpNuTQ=","keyUsage":["Digital Signature"],"extendedKeyUsage":["ExtKeyUsageServerAuth","ExtKeyUsageClientAuth"],"subjectAlternativeName":["*.google.com","*.android.com"],"crlDistributionPoint":["http://pki.google.com/GIAG2.crl"]},"x509v3BasicConstraints":"Critical","validationInfo":{"Android":{"isValid":true},"Apple":{"isValid":true},"Microsoft":{"isValid":true},"Mozilla":{"isValid":true},"Ubuntu":{"isValid":true}},"firstSeenTimestamp":"2015-12-03T20:29:14.540124Z","lastSeenTimestamp":"2015-12-05T14:18:27.723626Z","hashes":{"sha1":"72F15B6AA9A6DE87C098FE7662058D3EE0AA97BF","sha256":"E75D8D87D1712FBAACF0B9CDEC80C3AAEAB659A2D658917BB1402FA5A56DC5BB"},"Raw":""}`,
		},
		{
			expectedLevel: "modern",
			expectedFailures: []string{`sha1WithRSAEncryption is not a modern certificate signature, use sha256WithRSAEncryption or ecdsa-with-SHA256 or ecdsa-with-SHA384 or ecdsa-with-SHA512`,
				`consider adding ciphers ECDHE-ECDSA-AES256-GCM-SHA384, ECDHE-ECDSA-CHACHA20-POLY1305, ECDHE-RSA-CHACHA20-POLY1305, ECDHE-ECDSA-AES128-GCM-SHA256, ECDHE-ECDSA-AES256-SHA384, ECDHE-RSA-AES256-SHA384, ECDHE-ECDSA-AES128-SHA256, ECDHE-RSA-AES128-SHA256`},
			cipherscan:  `{"scanIP":"62.210.76.92","serverside":true,"ciphersuite":[{"cipher":"ECDHE-RSA-AES128-GCM-SHA256","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","ocsp_stapling":true,"pfs":"ECDH,P-384,384bits","curves":["secp384r1"]},{"cipher":"ECDHE-RSA-AES256-GCM-SHA384","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","ocsp_stapling":true,"pfs":"ECDH,P-384,384bits","curves":["secp384r1"]}]}`,
			certificate: `{"version":3,"signatureAlgorithm":"SHA1WithRSA","issuer":{"c":["US"],"o":["Google Inc"],"cn":"Google Internet Authority G2"},"validity":{"notBefore":"2015-11-26T00:09:43Z","notAfter":"2016-02-23T00:00:00Z"},"subject":{"c":["US"],"o":["Google Inc"],"cn":"*.google.com"},"subjectPublicKeyInfo":{"publicKeyAlgorithm":"RSA"},"x509v3Extensions":{"authorityKeyId":"St0GFhu89mi1dvWBtrtiGrpagS8=","subjectKeyId":"anFuWi3mReGqQcviW7pN+UpNuTQ=","keyUsage":["Digital Signature"],"extendedKeyUsage":["ExtKeyUsageServerAuth","ExtKeyUsageClientAuth"],"subjectAlternativeName":["*.google.com","*.android.com"],"crlDistributionPoint":["http://pki.google.com/GIAG2.crl"]},"x509v3BasicConstraints":"Critical","validationInfo":{"Android":{"isValid":true},"Apple":{"isValid":true},"Microsoft":{"isValid":true},"Mozilla":{"isValid":true},"Ubuntu":{"isValid":true}},"firstSeenTimestamp":"2015-12-03T20:29:14.540124Z","lastSeenTimestamp":"2015-12-05T14:18:27.723626Z","hashes":{"sha1":"72F15B6AA9A6DE87C098FE7662058D3EE0AA97BF","sha256":"E75D8D87D1712FBAACF0B9CDEC80C3AAEAB659A2D658917BB1402FA5A56DC5BB"},"Raw":""}`,
		},
		{
			expectedLevel:    "intermediate",
			expectedFailures: []string{`sha1WithRSAEncryption is not an intermediate certificate signature, use sha256WithRSAEncryption`},
			cipherscan:       `{"scanIP":"62.210.76.92","serverside":true,"ciphersuite":[{"cipher":"ECDHE-RSA-AES128-GCM-SHA256","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","ocsp_stapling":true,"pfs":"ECDH,P-384,384bits","curves":["secp384r1"]},{"cipher":"ECDHE-RSA-AES256-GCM-SHA384","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","ocsp_stapling":true,"pfs":"ECDH,P-384,384bits","curves":["secp384r1"]}]}`,
			certificate:      `{"version":3,"signatureAlgorithm":"SHA1WithRSA","issuer":{"c":["US"],"o":["Google Inc"],"cn":"Google Internet Authority G2"},"validity":{"notBefore":"2015-11-26T00:09:43Z","notAfter":"2016-02-23T00:00:00Z"},"subject":{"c":["US"],"o":["Google Inc"],"cn":"*.google.com"},"subjectPublicKeyInfo":{"publicKeyAlgorithm":"RSA"},"x509v3Extensions":{"authorityKeyId":"St0GFhu89mi1dvWBtrtiGrpagS8=","subjectKeyId":"anFuWi3mReGqQcviW7pN+UpNuTQ=","keyUsage":["Digital Signature"],"extendedKeyUsage":["ExtKeyUsageServerAuth","ExtKeyUsageClientAuth"],"subjectAlternativeName":["*.google.com","*.android.com"],"crlDistributionPoint":["http://pki.google.com/GIAG2.crl"]},"x509v3BasicConstraints":"Critical","validationInfo":{"Android":{"isValid":true},"Apple":{"isValid":true},"Microsoft":{"isValid":true},"Mozilla":{"isValid":true},"Ubuntu":{"isValid":true}},"firstSeenTimestamp":"2015-12-03T20:29:14.540124Z","lastSeenTimestamp":"2015-12-05T14:18:27.723626Z","hashes":{"sha1":"72F15B6AA9A6DE87C098FE7662058D3EE0AA97BF","sha256":"E75D8D87D1712FBAACF0B9CDEC80C3AAEAB659A2D658917BB1402FA5A56DC5BB"},"Raw":""}`,
		},
		{
			expectedLevel:    "intermediate",
			expectedFailures: []string{`remove cipher RC4-MD5`, `remove protocols SSLv3`, `add protocols TLSv1.1, TLSv1`},
			cipherscan:       `{"scanIP":"62.210.76.92","serverside":true,"ciphersuite":[{"cipher":"RC4-MD5","protocols":["TLSv1.2", "SSLv3"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","ocsp_stapling":true,"pfs":"ECDH,P-384,384bits","curves":["secp384r1"]}]}`,
			certificate:      `{"version":3,"signatureAlgorithm":"MD5WithRSA","issuer":{"c":["US"],"o":["Google Inc"],"cn":"Google Internet Authority G2"},"validity":{"notBefore":"2015-11-26T00:09:43Z","notAfter":"2016-02-23T00:00:00Z"},"subject":{"c":["US"],"o":["Google Inc"],"cn":"*.google.com"},"subjectPublicKeyInfo":{"publicKeyAlgorithm":"RSA"},"x509v3Extensions":{"authorityKeyId":"St0GFhu89mi1dvWBtrtiGrpagS8=","subjectKeyId":"anFuWi3mReGqQcviW7pN+UpNuTQ=","keyUsage":["Digital Signature"],"extendedKeyUsage":["ExtKeyUsageServerAuth","ExtKeyUsageClientAuth"],"subjectAlternativeName":["*.google.com","*.android.com"],"crlDistributionPoint":["http://pki.google.com/GIAG2.crl"]},"x509v3BasicConstraints":"Critical","validationInfo":{"Android":{"isValid":true},"Apple":{"isValid":true},"Microsoft":{"isValid":true},"Mozilla":{"isValid":true},"Ubuntu":{"isValid":true}},"firstSeenTimestamp":"2015-12-03T20:29:14.540124Z","lastSeenTimestamp":"2015-12-05T14:18:27.723626Z","hashes":{"sha1":"72F15B6AA9A6DE87C098FE7662058D3EE0AA97BF","sha256":"E75D8D87D1712FBAACF0B9CDEC80C3AAEAB659A2D658917BB1402FA5A56DC5BB"},"Raw":""}`,
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
		var cert certificate.Certificate
		err = json.Unmarshal([]byte(tp.certificate), &cert)
		if err != nil {
			t.Error("Failed to unmarshal test certificate")
			t.Error(err)
			t.Fail()
		}
		out, err := Evaluate(info, cert)
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
