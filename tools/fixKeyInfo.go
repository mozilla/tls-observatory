package main

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"github.com/mozilla/tls-observatory/certificate"
	"github.com/mozilla/tls-observatory/database"
)

func main() {
	db, err := database.RegisterConnection(
		os.Getenv("TLSOBS_POSTGRESDB"),
		os.Getenv("TLSOBS_POSTGRESUSER"),
		os.Getenv("TLSOBS_POSTGRESPASS"),
		os.Getenv("TLSOBS_POSTGRES"),
		"require")
	defer db.Close()
	if err != nil {
		panic(err)
	}
	// batch side: do 100 certs at a time
	limit := 100
	batch := 0
	for {
		fmt.Printf("\nProcessing batch %d to %d: ", batch*limit, batch*limit+limit)
		rows, err := db.Query(`SELECT id, raw_cert
					FROM certificates
					WHERE key_alg IS NULL
					ORDER BY id ASC LIMIT $1`, limit)
		if rows != nil {
			defer rows.Close()
		}
		if err != nil {
			panic(fmt.Errorf("Error while retrieving certs: '%v'", err))
		}
		i := 0
		for rows.Next() {
			i++
			var raw string
			var id int64
			err = rows.Scan(&id, &raw)
			if err != nil {
				fmt.Println("error while parsing cert", id, ":", err)
				continue
			}
			certdata, err := base64.StdEncoding.DecodeString(raw)
			if err != nil {
				fmt.Println("error decoding base64 of cert", id, ":", err)
				continue
			}
			c, err := x509.ParseCertificate(certdata)
			if err != nil {
				fmt.Println("error while x509 parsing cert", id, ":", err)
				continue
			}
			key, err := getPublicKeyInfo(c)
			if err != nil {
				fmt.Println("error while parsing public key info for cert", id, ":", err)
				continue
			}
			keydata, err := json.Marshal(key)
			if err != nil {
				fmt.Println("error while marshalling key info of cert", id, " : ", err)
				continue
			}

			pkp_sha256 := certificate.PKPSHA256Hash(c)

			_, err = db.Exec(`UPDATE certificates SET key=$1, key_alg=$2, pkp_sha256=$3 WHERE id=$4`,
				keydata, key.Alg, pkp_sha256, id)
			if err != nil {
				fmt.Println("error while updating cert", id, "in database:", err)
			}
		}
		if i == 0 {
			fmt.Println("done!")
			break
		}
		//offset += limit
		batch++
	}
}

func getPublicKeyInfo(cert *x509.Certificate) (certificate.SubjectPublicKeyInfo, error) {
	pubInfo := certificate.SubjectPublicKeyInfo{
		Alg: certificate.PublicKeyAlgorithm[cert.PublicKeyAlgorithm],
	}

	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		pubInfo.Size = float64(pub.N.BitLen())
		pubInfo.Exponent = float64(pub.E)

	case *dsa.PublicKey:
		pubInfo.Size = float64(pub.Y.BitLen())
		textInt, err := pub.G.MarshalText()

		if err == nil {
			pubInfo.G = string(textInt)
		} else {
			return pubInfo, err
		}

		textInt, err = pub.P.MarshalText()

		if err == nil {
			pubInfo.P = string(textInt)
		} else {
			return pubInfo, err
		}

		textInt, err = pub.Q.MarshalText()

		if err == nil {
			pubInfo.Q = string(textInt)
		} else {
			return pubInfo, err
		}

		textInt, err = pub.Y.MarshalText()

		if err == nil {
			pubInfo.Y = string(textInt)
		} else {
			return pubInfo, err
		}

	case *ecdsa.PublicKey:
		pubInfo.Size = float64(pub.Curve.Params().BitSize)
		pubInfo.Curve = pub.Curve.Params().Name
		pubInfo.Y = pub.Y.String()
		pubInfo.X = pub.X.String()
	}

	return pubInfo, nil

}
