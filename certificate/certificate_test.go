package certificate

import (
	"crypto/x509"
	"math/big"
	"testing"
)

func TestGetHexASN1Serial(t *testing.T) {
	type testcase struct {
		input  *x509.Certificate
		output string
	}
	testcases := []testcase{
		{
			&x509.Certificate{SerialNumber: big.NewInt(-1)},
			"FF",
		},
		{
			&x509.Certificate{SerialNumber: big.NewInt(1)},
			"01",
		},
		{
			&x509.Certificate{SerialNumber: big.NewInt(0)},
			"00",
		},
		{
			&x509.Certificate{SerialNumber: big.NewInt(201)},
			"00C9",
		},
		{
			&x509.Certificate{SerialNumber: big.NewInt(-201)},
			"FF37",
		},
	}
	for _, tc := range testcases {
		serial, _ := GetHexASN1Serial(tc.input)
		if serial != tc.output {
			t.Errorf("Expected %s, got %s", tc.output, serial)
		}
	}
}
