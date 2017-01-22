package mozillaEvaluationWorker

import (
	"encoding/json"
	"os"
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

func TestMain(m *testing.M) {
	err := json.Unmarshal([]byte(ServerSideTLSConfiguration), &sstls)
	if err != nil {
		log.Fatal("Could not load Server Side TLS configuration. Evaluation Worker not available")
	}
	modern = sstls.Configurations["modern"]
	intermediate = sstls.Configurations["intermediate"]
	old = sstls.Configurations["old"]

	r := m.Run()
	os.Exit(r)
}

func TestLevels(t *testing.T) {
	var tps = []testParams{
		{
			expectedLevel: "modern",
			cipherscan:    `{"scanIP":"62.210.76.92","serverside":true,"ciphersuite":[{"cipher":"ECDHE-RSA-AES128-GCM-SHA256","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","ocsp_stapling":true,"pfs":"ECDH,P-384,384bits","curves":["secp384r1"]},{"cipher":"ECDHE-RSA-AES256-GCM-SHA384","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","ocsp_stapling":true,"pfs":"ECDH,P-384,384bits","curves":["secp384r1"]},{"cipher":"ECDHE-RSA-AES128-SHA256","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","ocsp_stapling":true,"pfs":"ECDH,P-384,384bits","curves":["secp384r1"]},{"cipher":"ECDHE-RSA-AES256-SHA384","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","ocsp_stapling":true,"pfs":"ECDH,P-384,384bits","curves":["secp384r1"]}]}`,
			certificate:   `{"version":3,"signatureAlgorithm":"SHA256WithRSA","issuer":{"c":["US"],"o":["Let's Encrypt"],"cn":"Let's Encrypt Authority X3"},"validity":{"notBefore":"2016-05-01T09:52:00Z","notAfter":"2016-07-30T09:52:00Z"},"subject":{"cn":"ulfr.io"},"key":{"alg":"ECDSA","size":256,"x":"64926736612857395089195873273093428688429952940612592577870366260252436354438","y":"9984653055336340744748047648528099580334247564509354763572412395186599486389","curve":"P-256"},"x509v3Extensions":{"authorityKeyId":"qEpqYwR93brm0Tm3pkVl7/Oo7KE=","subjectKeyId":"cA69MCAkrwf8ItZkZpAfbf+ocPI=","keyUsage":["Digital Signature"],"extendedKeyUsage":["ExtKeyUsageServerAuth","ExtKeyUsageClientAuth"],"subjectAlternativeName":["jaffa.linuxwall.info","ulfr.io"],"crlDistributionPoint":null},"x509v3BasicConstraints":"Critical","validationInfo":{"Android":{"isValid":true},"Apple":{"isValid":true},"Microsoft":{"isValid":true},"Mozilla":{"isValid":true},"Ubuntu":{"isValid":true}},"firstSeenTimestamp":"2016-05-06T14:56:25.398571Z","lastSeenTimestamp":"2016-05-06T14:56:25.398571Z","hashes":{"sha1":"DA93EDBACB1A8E10FBCF22AA4360FA384F88EAB5","sha256":"CE535A99263D0A676EED629CD68F2748544D504BF39D00A461DCD140486374ED"}}`,
		},
		{
			expectedLevel: "intermediate",
			cipherscan:    `{"scanIP":"52.27.175.225","serverside":true,"ciphersuite":[{"cipher":"ECDHE-RSA-AES128-GCM-SHA256","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","pfs":"ECDH,P-256,256bits","curves":["prime256v1"]},{"cipher":"ECDHE-RSA-AES128-SHA256","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","pfs":"ECDH,P-256,256bits","curves":["prime256v1"]},{"cipher":"ECDHE-RSA-AES128-SHA","protocols":["TLSv1","TLSv1.1","TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","pfs":"ECDH,P-256,256bits","curves":["prime256v1"]},{"cipher":"DHE-RSA-AES128-SHA","protocols":["TLSv1","TLSv1.1","TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","pfs":"DH,2048bits"},{"cipher":"ECDHE-RSA-AES256-GCM-SHA384","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","pfs":"ECDH,P-256,256bits","curves":["prime256v1"]},{"cipher":"ECDHE-RSA-AES256-SHA384","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","pfs":"ECDH,P-256,256bits","curves":["prime256v1"]},{"cipher":"ECDHE-RSA-AES256-SHA","protocols":["TLSv1","TLSv1.1","TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","pfs":"ECDH,P-256,256bits","curves":["prime256v1"]},{"cipher":"AES128-GCM-SHA256","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","pfs":"None"},{"cipher":"AES128-SHA256","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","pfs":"None"},{"cipher":"AES128-SHA","protocols":["TLSv1","TLSv1.1","TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","pfs":"None"},{"cipher":"AES256-GCM-SHA384","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","pfs":"None"},{"cipher":"AES256-SHA256","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","pfs":"None"},{"cipher":"AES256-SHA","protocols":["TLSv1","TLSv1.1","TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","pfs":"None"},{"cipher":"DES-CBC3-SHA","protocols":["TLSv1","TLSv1.1","TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","pfs":"None"}]}`,
			certificate:   `{"version":3,"signatureAlgorithm":"SHA256WithRSA","issuer":{"c":["US"],"o":["DigiCert Inc"],"cn":"DigiCert SHA2 Secure Server CA"},"validity":{"notBefore":"2014-04-09T00:00:00Z","notAfter":"2017-04-12T12:00:00Z"},"subject":{"c":["US"],"o":["Mozilla Corporation"],"cn":"accounts.firefox.com"},"key":{"alg":"RSA","size":2048,"exponent":65537},"x509v3Extensions":{"authorityKeyId":"D4BhHIIxYdUvKOeNRji0LOHG2eI=","subjectKeyId":"202e69jd3RcFpGdnCnnzzmz5zEA=","keyUsage":["Digital Signature","Key Encipherment"],"extendedKeyUsage":["ExtKeyUsageServerAuth","ExtKeyUsageClientAuth"],"subjectAlternativeName":["accounts.firefox.com","api.accounts.firefox.com","scrypt.accounts.firefox.com","verifier.accounts.firefox.com","oauth.accounts.firefox.com","profile.accounts.firefox.com"],"crlDistributionPoint":["http://crl3.digicert.com/ssca-sha2-g2.crl","http://crl4.digicert.com/ssca-sha2-g2.crl"]},"x509v3BasicConstraints":"Critical","validationInfo":{"Android":{"isValid":true},"Apple":{"isValid":true},"Microsoft":{"isValid":true},"Mozilla":{"isValid":true},"Ubuntu":{"isValid":true}},"firstSeenTimestamp":"2016-05-06T15:35:38.027236Z","lastSeenTimestamp":"2016-05-06T15:35:38.027236Z","hashes":{"sha1":"E4289BE190C8DCAE983446B44CEAE3C32FED7465","sha256":"578CC616243D5B7AE48D83F834D498693B5C7ED5E9C406A9985CAB5FB7C9807B"}}`,
		},
		{
			expectedLevel: "old",
			cipherscan:    `{"scanIP":"63.245.215.20","serverside":true,"ciphersuite":[{"cipher":"ECDHE-RSA-AES128-GCM-SHA256","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha1WithRSAEncryption","ticket_hint":"None","ocsp_stapling":true,"pfs":"ECDH,P-256,256bits","curves":["prime256v1","secp384r1","secp521r1"]},{"cipher":"ECDHE-RSA-AES256-GCM-SHA384","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha1WithRSAEncryption","ticket_hint":"None","ocsp_stapling":true,"pfs":"ECDH,P-256,256bits","curves":["prime256v1","secp384r1","secp521r1"]},{"cipher":"ECDHE-RSA-AES128-SHA256","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha1WithRSAEncryption","ticket_hint":"None","ocsp_stapling":true,"pfs":"ECDH,P-256,256bits","curves":["prime256v1","secp384r1","secp521r1"]},{"cipher":"ECDHE-RSA-AES256-SHA384","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha1WithRSAEncryption","ticket_hint":"None","ocsp_stapling":true,"pfs":"ECDH,P-256,256bits","curves":["prime256v1","secp384r1","secp521r1"]},{"cipher":"ECDHE-RSA-AES128-SHA","protocols":["TLSv1","TLSv1.1","TLSv1.2"],"pubkey":2048,"sigalg":"sha1WithRSAEncryption","ticket_hint":"None","ocsp_stapling":true,"pfs":"ECDH,P-256,256bits","curves":["prime256v1","secp384r1","secp521r1"]},{"cipher":"ECDHE-RSA-AES256-SHA","protocols":["TLSv1","TLSv1.1","TLSv1.2"],"pubkey":2048,"sigalg":"sha1WithRSAEncryption","ticket_hint":"None","ocsp_stapling":true,"pfs":"ECDH,P-256,256bits","curves":["prime256v1","secp384r1","secp521r1"]},{"cipher":"DHE-RSA-AES128-GCM-SHA256","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha1WithRSAEncryption","ticket_hint":"None","ocsp_stapling":true,"pfs":"DH,1024bits"},{"cipher":"DHE-RSA-AES256-GCM-SHA384","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha1WithRSAEncryption","ticket_hint":"None","ocsp_stapling":true,"pfs":"DH,1024bits"},{"cipher":"DHE-RSA-AES128-SHA256","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha1WithRSAEncryption","ticket_hint":"None","ocsp_stapling":true,"pfs":"DH,1024bits"},{"cipher":"DHE-RSA-AES256-SHA256","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha1WithRSAEncryption","ticket_hint":"None","ocsp_stapling":true,"pfs":"DH,1024bits"},{"cipher":"AES128-GCM-SHA256","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha1WithRSAEncryption","ticket_hint":"None","ocsp_stapling":true,"pfs":"None"},{"cipher":"AES256-GCM-SHA384","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha1WithRSAEncryption","ticket_hint":"None","ocsp_stapling":true,"pfs":"None"},{"cipher":"AES128-SHA256","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha1WithRSAEncryption","ticket_hint":"None","ocsp_stapling":true,"pfs":"None"},{"cipher":"AES256-SHA256","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha1WithRSAEncryption","ticket_hint":"None","ocsp_stapling":true,"pfs":"None"},{"cipher":"DES-CBC3-SHA","protocols":["SSLv3","TLSv1","TLSv1.1","TLSv1.2"],"pubkey":2048,"sigalg":"sha1WithRSAEncryption","ticket_hint":"None","ocsp_stapling":true,"pfs":"None"}]}`,
			certificate:   `{"version":3,"signatureAlgorithm":"SHA1WithRSA","issuer":{"c":["US"],"o":["DigiCert Inc"],"ou":["www.digicert.com"],"cn":"DigiCert High Assurance EV CA-1"},"validity":{"notBefore":"2015-11-24T00:00:00Z","notAfter":"2016-12-29T12:00:00Z"},"subject":{"c":["US"],"o":["Mozilla Foundation"],"cn":"www.mozilla.org"},"key":{"alg":"RSA","size":2048,"exponent":65537},"x509v3Extensions":{"authorityKeyId":"TFjLJfBBT1L0KMiBQ5umqKDmkuU=","subjectKeyId":"g9TUDzWkuou+YTdiwZYNNsfHNzk=","keyUsage":["Digital Signature","Key Encipherment"],"extendedKeyUsage":["ExtKeyUsageServerAuth","ExtKeyUsageClientAuth"],"subjectAlternativeName":["www.mozilla.org","mozilla.org"],"crlDistributionPoint":["http://crl3.digicert.com/evca1-g5.crl","http://crl4.digicert.com/evca1-g5.crl"]},"x509v3BasicConstraints":"Critical","validationInfo":{"Android":{"isValid":true},"Apple":{"isValid":true},"Microsoft":{"isValid":true},"Mozilla":{"isValid":true},"Ubuntu":{"isValid":true}},"firstSeenTimestamp":"2016-05-06T15:34:52.183044Z","lastSeenTimestamp":"2016-05-06T15:34:52.183044Z","hashes":{"sha1":"D0AA5BBE9824A4A0C5B6BB9ACF258FAB7E6EF2F5","sha256":"B4D02324CF8AB6BB6B3266BED887F645A312482467C9370D0D00F93E9DDE6530"}}`,
		},
		{
			expectedLevel: "bad",
			cipherscan:    `{"scanIP":"62.210.76.92","serverside":true,"ciphersuite":[{"cipher":"RC4-MD5","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","ocsp_stapling":true,"pfs":"ECDH,P-384,384bits","curves":["secp384r1"]},{"cipher":"ECDHE-RSA-AES256-GCM-SHA384","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","ocsp_stapling":true,"pfs":"ECDH,P-384,384bits","curves":["secp384r1"]},{"cipher":"ECDHE-RSA-AES128-SHA256","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","ocsp_stapling":true,"pfs":"ECDH,P-384,384bits","curves":["secp384r1"]},{"cipher":"ECDHE-RSA-AES256-SHA384","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","ocsp_stapling":true,"pfs":"ECDH,P-384,384bits","curves":["secp384r1"]}]}`,
			certificate:   `{"version":3,"signatureAlgorithm":"MD5WithRSA","issuer":{"c":["US"],"o":["Google Inc"],"cn":"Google Internet Authority G2"},"validity":{"notBefore":"2015-11-26T00:09:43Z","notAfter":"2016-02-23T00:00:00Z"},"subject":{"c":["US"],"o":["Google Inc"],"cn":"*.google.com"},"subjectPublicKeyInfo":{"publicKeyAlgorithm":"RSA"},"x509v3Extensions":{"authorityKeyId":"St0GFhu89mi1dvWBtrtiGrpagS8=","subjectKeyId":"anFuWi3mReGqQcviW7pN+UpNuTQ=","keyUsage":["Digital Signature"],"extendedKeyUsage":["ExtKeyUsageServerAuth","ExtKeyUsageClientAuth"],"subjectAlternativeName":["*.google.com","*.android.com"],"crlDistributionPoint":["http://pki.google.com/GIAG2.crl"]},"x509v3BasicConstraints":"Critical","validationInfo":{"Android":{"isValid":true},"Apple":{"isValid":true},"Microsoft":{"isValid":true},"Mozilla":{"isValid":true},"Ubuntu":{"isValid":true}},"firstSeenTimestamp":"2015-12-03T20:29:14.540124Z","lastSeenTimestamp":"2015-12-05T14:18:27.723626Z","hashes":{"sha1":"72F15B6AA9A6DE87C098FE7662058D3EE0AA97BF","sha256":"E75D8D87D1712FBAACF0B9CDEC80C3AAEAB659A2D658917BB1402FA5A56DC5BB"},"Raw":""}`,
		},
	}
	for i, tp := range tps {
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
			t.Error("In test case", i, ", measured level", results.Level, "does not match expected of", tp.expectedLevel)
			t.Logf("%s: %+v", tp.expectedLevel, results.Failures[tp.expectedLevel])
			t.Logf("bad: %+v", results.Failures["bad"])
			t.Logf("ciphers: %+v", info)
			t.Logf("cert: %+v", cert)
			t.Fail()
		}
	}
}

func TestFailures(t *testing.T) {
	var tps = []testParams{
		{
			expectedLevel:    "bad",
			expectedFailures: []string{`don't use a key smaller than 2048bits (RSA) or 256bits (ECDSA)`},
			cipherscan:       `{"scanIP":"62.210.76.92","serverside":true,"ciphersuite":[{"cipher":"ECDHE-RSA-AES128-GCM-SHA256","protocols":["TLSv1.2"],"pubkey":512,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","ocsp_stapling":true,"pfs":"ECDH,P-384,384bits","curves":["secp384r1"]}]}`,
			certificate:      `{"version":3,"key":{"alg":"RSA","size":512,"exponent":65537},"signatureAlgorithm":"MD5WithRSA","issuer":{"c":["US"],"o":["Google Inc"],"cn":"Google Internet Authority G2"},"validity":{"notBefore":"2015-11-26T00:09:43Z","notAfter":"2016-02-23T00:00:00Z"},"subject":{"c":["US"],"o":["Google Inc"],"cn":"*.google.com"},"subjectPublicKeyInfo":{"publicKeyAlgorithm":"RSA"},"x509v3Extensions":{"authorityKeyId":"St0GFhu89mi1dvWBtrtiGrpagS8=","subjectKeyId":"anFuWi3mReGqQcviW7pN+UpNuTQ=","keyUsage":["Digital Signature"],"extendedKeyUsage":["ExtKeyUsageServerAuth","ExtKeyUsageClientAuth"],"subjectAlternativeName":["*.google.com","*.android.com"],"crlDistributionPoint":["http://pki.google.com/GIAG2.crl"]},"x509v3BasicConstraints":"Critical","validationInfo":{"Android":{"isValid":true},"Apple":{"isValid":true},"Microsoft":{"isValid":true},"Mozilla":{"isValid":true},"Ubuntu":{"isValid":true}},"firstSeenTimestamp":"2015-12-03T20:29:14.540124Z","lastSeenTimestamp":"2015-12-05T14:18:27.723626Z","hashes":{"sha1":"72F15B6AA9A6DE87C098FE7662058D3EE0AA97BF","sha256":"E75D8D87D1712FBAACF0B9CDEC80C3AAEAB659A2D658917BB1402FA5A56DC5BB"},"Raw":""}`,
		},
		{
			expectedLevel:    "bad",
			expectedFailures: []string{`don't use a key smaller than 2048bits (RSA) or 256bits (ECDSA)`},
			cipherscan:       `{"scanIP":"62.210.76.92","serverside":true,"ciphersuite":[{"cipher":"ECDHE-RSA-AES128-GCM-SHA256","protocols":["TLSv1.2"],"pubkey":512,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","ocsp_stapling":true,"pfs":"ECDH,P-384,384bits","curves":["secp384r1"]}]}`,
			certificate:      `{"version":3,"key":{"alg":"ECDSA","size":160},"signatureAlgorithm":"MD5WithRSA","issuer":{"c":["US"],"o":["Google Inc"],"cn":"Google Internet Authority G2"},"validity":{"notBefore":"2015-11-26T00:09:43Z","notAfter":"2016-02-23T00:00:00Z"},"subject":{"c":["US"],"o":["Google Inc"],"cn":"*.google.com"},"subjectPublicKeyInfo":{"publicKeyAlgorithm":"RSA"},"x509v3Extensions":{"authorityKeyId":"St0GFhu89mi1dvWBtrtiGrpagS8=","subjectKeyId":"anFuWi3mReGqQcviW7pN+UpNuTQ=","keyUsage":["Digital Signature"],"extendedKeyUsage":["ExtKeyUsageServerAuth","ExtKeyUsageClientAuth"],"subjectAlternativeName":["*.google.com","*.android.com"],"crlDistributionPoint":["http://pki.google.com/GIAG2.crl"]},"x509v3BasicConstraints":"Critical","validationInfo":{"Android":{"isValid":true},"Apple":{"isValid":true},"Microsoft":{"isValid":true},"Mozilla":{"isValid":true},"Ubuntu":{"isValid":true}},"firstSeenTimestamp":"2015-12-03T20:29:14.540124Z","lastSeenTimestamp":"2015-12-05T14:18:27.723626Z","hashes":{"sha1":"72F15B6AA9A6DE87C098FE7662058D3EE0AA97BF","sha256":"E75D8D87D1712FBAACF0B9CDEC80C3AAEAB659A2D658917BB1402FA5A56DC5BB"},"Raw":""}`,
		},
		{
			expectedLevel:    "modern",
			expectedFailures: []string{`fix ciphersuite ordering, use recommended modern ciphersuite`},
			cipherscan:       `{"scanIP":"62.210.76.92","serverside":true,"ciphersuite":[{"cipher":"ECDHE-RSA-AES128-GCM-SHA256","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","ocsp_stapling":true,"pfs":"ECDH,P-384,384bits","curves":["secp384r1"]},{"cipher":"ECDHE-RSA-AES256-GCM-SHA384","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","ocsp_stapling":true,"pfs":"ECDH,P-384,384bits","curves":["secp384r1"]}]}`,
			certificate:      `{"version":3,"key":{"alg":"ECDSA","size":256},"signatureAlgorithm":"ECDSAWithSHA256","issuer":{"c":["US"],"o":["Google Inc"],"cn":"Google Internet Authority G2"},"validity":{"notBefore":"2015-11-26T00:09:43Z","notAfter":"2016-02-23T00:00:00Z"},"subject":{"c":["US"],"o":["Google Inc"],"cn":"*.google.com"},"subjectPublicKeyInfo":{"publicKeyAlgorithm":"ECDSA"},"x509v3Extensions":{"authorityKeyId":"St0GFhu89mi1dvWBtrtiGrpagS8=","subjectKeyId":"anFuWi3mReGqQcviW7pN+UpNuTQ=","keyUsage":["Digital Signature"],"extendedKeyUsage":["ExtKeyUsageServerAuth","ExtKeyUsageClientAuth"],"subjectAlternativeName":["*.google.com","*.android.com"],"crlDistributionPoint":["http://pki.google.com/GIAG2.crl"]},"x509v3BasicConstraints":"Critical","validationInfo":{"Android":{"isValid":true},"Apple":{"isValid":true},"Microsoft":{"isValid":true},"Mozilla":{"isValid":true},"Ubuntu":{"isValid":true}},"firstSeenTimestamp":"2015-12-03T20:29:14.540124Z","lastSeenTimestamp":"2015-12-05T14:18:27.723626Z","hashes":{"sha1":"72F15B6AA9A6DE87C098FE7662058D3EE0AA97BF","sha256":"E75D8D87D1712FBAACF0B9CDEC80C3AAEAB659A2D658917BB1402FA5A56DC5BB"},"Raw":""}`,
		},
		{
			expectedLevel:    "modern",
			expectedFailures: []string{`enable Perfect Forward Secrecy with a curve of at least 256bits, don't use DHE`, `remove ciphersuites DHE-RSA-AES128-GCM-SHA256`},
			cipherscan:       `{"scanIP":"62.210.76.92","serverside":true,"ciphersuite":[{"cipher":"ECDHE-RSA-AES128-GCM-SHA256","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","ocsp_stapling":true,"pfs":"ECDH,P-384,384bits","curves":["secp384r1"]},{"cipher":"ECDHE-RSA-AES256-GCM-SHA384","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","ocsp_stapling":true,"pfs":"ECDH,P-384,384bits","curves":["secp384r1"]},{"cipher":"DHE-RSA-AES128-GCM-SHA256","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha1WithRSAEncryption","ticket_hint":"None","ocsp_stapling":true,"pfs":"DH,1024bits"}]}`,
			certificate:      `{"version":3,"key":{"alg":"ECDSA","size":256},"signatureAlgorithm":"ECDSAWithSHA256","issuer":{"c":["US"],"o":["Google Inc"],"cn":"Google Internet Authority G2"},"validity":{"notBefore":"2015-11-26T00:09:43Z","notAfter":"2016-02-23T00:00:00Z"},"subject":{"c":["US"],"o":["Google Inc"],"cn":"*.google.com"},"subjectPublicKeyInfo":{"publicKeyAlgorithm":"ECDSA"},"x509v3Extensions":{"authorityKeyId":"St0GFhu89mi1dvWBtrtiGrpagS8=","subjectKeyId":"anFuWi3mReGqQcviW7pN+UpNuTQ=","keyUsage":["Digital Signature"],"extendedKeyUsage":["ExtKeyUsageServerAuth","ExtKeyUsageClientAuth"],"subjectAlternativeName":["*.google.com","*.android.com"],"crlDistributionPoint":["http://pki.google.com/GIAG2.crl"]},"x509v3BasicConstraints":"Critical","validationInfo":{"Android":{"isValid":true},"Apple":{"isValid":true},"Microsoft":{"isValid":true},"Mozilla":{"isValid":true},"Ubuntu":{"isValid":true}},"firstSeenTimestamp":"2015-12-03T20:29:14.540124Z","lastSeenTimestamp":"2015-12-05T14:18:27.723626Z","hashes":{"sha1":"72F15B6AA9A6DE87C098FE7662058D3EE0AA97BF","sha256":"E75D8D87D1712FBAACF0B9CDEC80C3AAEAB659A2D658917BB1402FA5A56DC5BB"},"Raw":""}`,
		},
		{
			expectedLevel: "modern",
			expectedFailures: []string{`sha1WithRSAEncryption is not a modern certificate signature, use sha256WithRSAEncryption or ecdsa-with-SHA256 or ecdsa-with-SHA384 or ecdsa-with-SHA512`,
				`consider adding ciphers ECDHE-ECDSA-AES256-GCM-SHA384, ECDHE-ECDSA-CHACHA20-POLY1305, ECDHE-RSA-CHACHA20-POLY1305, ECDHE-ECDSA-AES128-GCM-SHA256, ECDHE-ECDSA-AES256-SHA384, ECDHE-RSA-AES256-SHA384, ECDHE-ECDSA-AES128-SHA256, ECDHE-RSA-AES128-SHA256`},
			cipherscan:  `{"scanIP":"62.210.76.92","serverside":true,"ciphersuite":[{"cipher":"ECDHE-RSA-AES128-GCM-SHA256","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","ocsp_stapling":true,"pfs":"ECDH,P-384,384bits","curves":["secp384r1"]},{"cipher":"ECDHE-RSA-AES256-GCM-SHA384","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","ocsp_stapling":true,"pfs":"ECDH,P-384,384bits","curves":["secp384r1"]}]}`,
			certificate: `{"version":3,"key":{"alg":"RSA","size":2048},"signatureAlgorithm":"SHA1WithRSA","issuer":{"c":["US"],"o":["Google Inc"],"cn":"Google Internet Authority G2"},"validity":{"notBefore":"2015-11-26T00:09:43Z","notAfter":"2016-02-23T00:00:00Z"},"subject":{"c":["US"],"o":["Google Inc"],"cn":"*.google.com"},"subjectPublicKeyInfo":{"publicKeyAlgorithm":"RSA"},"x509v3Extensions":{"authorityKeyId":"St0GFhu89mi1dvWBtrtiGrpagS8=","subjectKeyId":"anFuWi3mReGqQcviW7pN+UpNuTQ=","keyUsage":["Digital Signature"],"extendedKeyUsage":["ExtKeyUsageServerAuth","ExtKeyUsageClientAuth"],"subjectAlternativeName":["*.google.com","*.android.com"],"crlDistributionPoint":["http://pki.google.com/GIAG2.crl"]},"x509v3BasicConstraints":"Critical","validationInfo":{"Android":{"isValid":true},"Apple":{"isValid":true},"Microsoft":{"isValid":true},"Mozilla":{"isValid":true},"Ubuntu":{"isValid":true}},"firstSeenTimestamp":"2015-12-03T20:29:14.540124Z","lastSeenTimestamp":"2015-12-05T14:18:27.723626Z","hashes":{"sha1":"72F15B6AA9A6DE87C098FE7662058D3EE0AA97BF","sha256":"E75D8D87D1712FBAACF0B9CDEC80C3AAEAB659A2D658917BB1402FA5A56DC5BB"},"Raw":""}`,
		},
		{
			expectedLevel:    "intermediate",
			expectedFailures: []string{`sha1WithRSAEncryption is not an intermediate certificate signature, use sha256WithRSAEncryption`},
			cipherscan:       `{"scanIP":"62.210.76.92","serverside":true,"ciphersuite":[{"cipher":"ECDHE-RSA-AES128-GCM-SHA256","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","ocsp_stapling":true,"pfs":"ECDH,P-384,384bits","curves":["secp384r1"]},{"cipher":"ECDHE-RSA-AES256-GCM-SHA384","protocols":["TLSv1.2"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","ocsp_stapling":true,"pfs":"ECDH,P-384,384bits","curves":["secp384r1"]}]}`,
			certificate:      `{"version":3,"key":{"alg":"RSA","size":2048},"signatureAlgorithm":"SHA1WithRSA","issuer":{"c":["US"],"o":["Google Inc"],"cn":"Google Internet Authority G2"},"validity":{"notBefore":"2015-11-26T00:09:43Z","notAfter":"2016-02-23T00:00:00Z"},"subject":{"c":["US"],"o":["Google Inc"],"cn":"*.google.com"},"subjectPublicKeyInfo":{"publicKeyAlgorithm":"RSA"},"x509v3Extensions":{"authorityKeyId":"St0GFhu89mi1dvWBtrtiGrpagS8=","subjectKeyId":"anFuWi3mReGqQcviW7pN+UpNuTQ=","keyUsage":["Digital Signature"],"extendedKeyUsage":["ExtKeyUsageServerAuth","ExtKeyUsageClientAuth"],"subjectAlternativeName":["*.google.com","*.android.com"],"crlDistributionPoint":["http://pki.google.com/GIAG2.crl"]},"x509v3BasicConstraints":"Critical","validationInfo":{"Android":{"isValid":true},"Apple":{"isValid":true},"Microsoft":{"isValid":true},"Mozilla":{"isValid":true},"Ubuntu":{"isValid":true}},"firstSeenTimestamp":"2015-12-03T20:29:14.540124Z","lastSeenTimestamp":"2015-12-05T14:18:27.723626Z","hashes":{"sha1":"72F15B6AA9A6DE87C098FE7662058D3EE0AA97BF","sha256":"E75D8D87D1712FBAACF0B9CDEC80C3AAEAB659A2D658917BB1402FA5A56DC5BB"},"Raw":""}`,
		},
		{
			expectedLevel:    "intermediate",
			expectedFailures: []string{`remove ciphersuites RC4-MD5`, `remove protocols SSLv3`, `add protocols TLSv1.1, TLSv1`},
			cipherscan:       `{"scanIP":"62.210.76.92","serverside":true,"ciphersuite":[{"cipher":"RC4-MD5","protocols":["TLSv1.2", "SSLv3"],"pubkey":2048,"sigalg":"sha256WithRSAEncryption","ticket_hint":"300","ocsp_stapling":true,"pfs":"ECDH,P-384,384bits","curves":["secp384r1"]}]}`,
			certificate:      `{"version":3,"key":{"alg":"RSA","size":2048},"signatureAlgorithm":"MD5WithRSA","issuer":{"c":["US"],"o":["Google Inc"],"cn":"Google Internet Authority G2"},"validity":{"notBefore":"2015-11-26T00:09:43Z","notAfter":"2016-02-23T00:00:00Z"},"subject":{"c":["US"],"o":["Google Inc"],"cn":"*.google.com"},"subjectPublicKeyInfo":{"publicKeyAlgorithm":"RSA"},"x509v3Extensions":{"authorityKeyId":"St0GFhu89mi1dvWBtrtiGrpagS8=","subjectKeyId":"anFuWi3mReGqQcviW7pN+UpNuTQ=","keyUsage":["Digital Signature"],"extendedKeyUsage":["ExtKeyUsageServerAuth","ExtKeyUsageClientAuth"],"subjectAlternativeName":["*.google.com","*.android.com"],"crlDistributionPoint":["http://pki.google.com/GIAG2.crl"]},"x509v3BasicConstraints":"Critical","validationInfo":{"Android":{"isValid":true},"Apple":{"isValid":true},"Microsoft":{"isValid":true},"Mozilla":{"isValid":true},"Ubuntu":{"isValid":true}},"firstSeenTimestamp":"2015-12-03T20:29:14.540124Z","lastSeenTimestamp":"2015-12-05T14:18:27.723626Z","hashes":{"sha1":"72F15B6AA9A6DE87C098FE7662058D3EE0AA97BF","sha256":"E75D8D87D1712FBAACF0B9CDEC80C3AAEAB659A2D658917BB1402FA5A56DC5BB"},"Raw":""}`,
		},
	}
	for i, tp := range tps {
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
				t.Errorf("In test case %d, expected failure %q not found in results", i, ef)
				t.Logf("%s: %+v", tp.expectedLevel, results.Failures[tp.expectedLevel])
				t.Fail()
			}
		}
	}
}
