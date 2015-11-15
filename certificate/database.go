package certificate

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/Sirupsen/logrus"

	pg "github.com/mozilla/TLS-Observer/modules/postgresmodule"
)

var db *pg.DB

func InsertCertificatetoDB(cert *Certificate) (int64, error) {

	var id int64

	err := db.QueryRow(`INSERT INTO certificates(  sha1_fingerprint, sha256_fingerprint,
	issuer, subject, version, is_ca, not_valid_before, not_valid_after,
	first_seen, last_seen, x509_basicConstraints, x509_crlDistributionPoints, x509_extendedKeyUsage,
	x509_authorityKeyIdentifier, x509_subjectKeyIdentifier, x509_keyUsage, x509_subjectAltName,
	signature_algo, raw_cert ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11,
	$12, $13, $14, $15, $16, $17, $18, $19) RETURNING id`,
		cert.Hashes.SHA1, cert.Hashes.SHA256, cert.Issuer.CommonName, cert.Subject.CommonName,
		cert.Version, cert.CA, time.Now(), time.Now(), time.Now(),
		time.Now(), cert.X509v3BasicConstraints, pg.StringSliceToString(cert.X509v3Extensions.CRLDistributionPoints),
		pg.StringSliceToString(cert.X509v3Extensions.ExtendedKeyUsage), string(cert.X509v3Extensions.AuthorityKeyId),
		string(cert.X509v3Extensions.SubjectKeyId), pg.StringSliceToString(cert.X509v3Extensions.KeyUsage),
		pg.StringSliceToString(cert.X509v3Extensions.SubjectAlternativeName), cert.SignatureAlgorithm, cert.Raw).Scan(&id)

	if err != nil {
		return -1, err
	}

	return id, nil
}

func UpdateCertLastSeen(cert *Certificate) error {

	_, err := db.Exec("UPDATE certificates SET last_seen=$1 WHERE sha1_fingerprint=$2", cert.LastSeenTimestamp, cert.Hashes.SHA1)
	return err
}

func UpdateCertLastSeenWithID(id int64) error {

	_, err := db.Exec("UPDATE certificates SET last_seen=$1 WHERE id=$2", time.Now(), id)
	return err
}

func GetCertIDWithSHA1Fingerprint(sha1 string) (int64, error) {

	query := fmt.Sprintf(`SELECT id FROM certificates WHERE sha1_fingerprint='%s'`, sha1)

	row := db.QueryRow(query)

	var id int64

	err := row.Scan(&id)

	if err != nil {
		if err == sql.ErrNoRows {
			return -1, nil
		} else {
			return -1, err
		}
	} else {
		return id, nil
	}
}

func GetCertIDWithSHA256Fingerprint(sha256 string) (int64, error) {

	query := fmt.Sprintf(`SELECT id FROM certificates WHERE sha256_fingerprint='%s'`, sha256)

	row := db.QueryRow(query)

	var id int64

	err := row.Scan(&id)

	if err != nil {
		if err == sql.ErrNoRows {
			return -1, nil
		} else {
			return -1, err
		}
	} else {
		return id, nil
	}
}

func GetCertIDFromTrust(trustID int64) (int64, error) {

	row := db.QueryRow("SELECT cert_id FROM trust WHERE id=$1", trustID)

	var id int64

	err := row.Scan(&id)

	if err != nil {
		if err == sql.ErrNoRows {
			return -1, nil
		} else {
			return -1, err
		}
	} else {
		return id, nil
	}

}

func GetCertwithSHA1Fingerprint(sha1 string) (*Certificate, error) {

	row := db.QueryRow(`SELECT sha256_fingerprint,
		issuer, subject, version, is_ca, valid_not_before, valid_not_after, 
		first_seen, last_Seen, x509_basicConstraints, x509_crlDistPoints, x509_extendedKeyUsage
		x509_authorityKeyIdentifier, x509_subjectKeyIdentifier, x509_keyUsage, x509_subjectAltName,
		signature_algo, parent_id, raw_cert
		FROM certificates
		WHERE sha1_fingerprint=$1`, sha1)

	cert := &Certificate{}

	var crl_dist_points, extkeyusage, keyusage, subaltname string

	err := row.Scan(&cert.Hashes.SHA256, &cert.Issuer.CommonName, &cert.Subject.CommonName,
		&cert.Version, &cert.CA, &cert.Validity.NotBefore, &cert.Validity.NotAfter, &cert.FirstSeenTimestamp,
		&cert.LastSeenTimestamp, &cert.X509v3BasicConstraints, &crl_dist_points,
		&extkeyusage, &cert.X509v3Extensions.AuthorityKeyId,
		&cert.X509v3Extensions.SubjectKeyId, &keyusage,
		&subaltname, &cert.SignatureAlgorithm,
		&cert.ParentSignature)

	if err != nil {
		return nil, err
	}

	cert.X509v3Extensions.CRLDistributionPoints = pg.StringToStringSlice(crl_dist_points)
	cert.X509v3Extensions.ExtendedKeyUsage = pg.StringToStringSlice(extkeyusage)
	cert.X509v3Extensions.KeyUsage = pg.StringToStringSlice(keyusage)
	cert.X509v3Extensions.SubjectAlternativeName = pg.StringToStringSlice(subaltname)

	return cert, nil

}

func GetCertwithID(id string) (*Certificate, error) {

	row := db.QueryRow(`SELECT sha1_fingerprint,sha256_fingerprint,
		issuer, subject, version, is_ca, valid_not_before, valid_not_after, 
		first_seen, last_Seen, x509_basicConstraints, x509_crlDistPoints, x509_extendedKeyUsage
		x509_authorityKeyIdentifier, x509_subjectKeyIdentifier, x509_keyUsage, x509_subjectAltName,
		signature_algo, parent_id, raw_cert
		FROM certificates
		WHERE id=$1`, id)

	cert := &Certificate{}

	err := row.Scan(&cert.Hashes.SHA1, &cert.Hashes.SHA256, &cert.Issuer.CommonName, &cert.Subject.CommonName,
		&cert.Version, &cert.CA, &cert.Validity.NotBefore, &cert.Validity.NotAfter, &cert.FirstSeenTimestamp,
		&cert.LastSeenTimestamp, &cert.X509v3BasicConstraints, &cert.X509v3Extensions.CRLDistributionPoints,
		&cert.X509v3Extensions.ExtendedKeyUsage, &cert.X509v3Extensions.AuthorityKeyId,
		&cert.X509v3Extensions.SubjectKeyId, &cert.X509v3Extensions.KeyUsage,
		&cert.X509v3Extensions.SubjectAlternativeName, &cert.SignatureAlgorithm,
		&cert.ParentSignature)

	if err != nil {
		return nil, err
	} else {
		return cert, nil
	}

}

func insertTrustToDB(cert Certificate, certID, parID int64) (int64, error) {

	var trustID int64

	trusted_ubuntu, trusted_mozilla, trusted_microsoft, trusted_apple, trusted_android := cert.GetBooleanValidity()

	err := db.QueryRow(`INSERT INTO trust(cert_id,issuer_id,timestamp,trusted_ubuntu,trusted_mozilla,trusted_microsoft,trusted_apple,trusted_android,is_current)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id`, certID, parID, time.Now(), trusted_ubuntu, trusted_mozilla, trusted_microsoft, trusted_apple, trusted_android, true).Scan(&trustID)

	if err != nil {
		return -1, err
	}

	return trustID, nil

}

func updateTrust(trustID int64, cert Certificate) (int64, error) {

	var trusted_ubuntu, trusted_mozilla, trusted_microsoft, trusted_apple, trusted_android bool

	var certID, parID int64

	err := db.QueryRow(`SELECT cert_id, issuer_id, trusted_ubuntu, trusted_mozilla, trusted_microsoft, trusted_apple, trusted_android FROM trust WHERE id=$1 AND is_current=TRUE`,
		trustID).Scan(&certID, &parID, &trusted_ubuntu, &trusted_mozilla, &trusted_microsoft, &trusted_apple, &trusted_android)

	if err != nil {
		return -1, err
	}

	new_ubuntu, new_mozilla, new_microsoft, new_apple, new_android := cert.GetBooleanValidity()

	isTrustCurrent := true

	if trusted_ubuntu != new_ubuntu || trusted_mozilla != new_mozilla || trusted_microsoft != new_microsoft || trusted_apple != new_apple || trusted_android != new_android {
		isTrustCurrent = false
	}

	if !isTrustCurrent { // create new trust and obsolete old one

		newID, err := insertTrustToDB(cert, certID, parID)

		if err != nil {

			log.WithFields(logrus.Fields{
				"to_obsolete": trustID,
				"error":       err.Error(),
			}).Error("Could not add new/current trust")

			return -1, err
		}

		_, err = db.Exec("UPDATE trust SET is_current=$1 WHERE id=$2", false, trustID)

		if err != nil {

			log.WithFields(logrus.Fields{
				"obsolete_trust_id": trustID,
				"error":             err.Error(),
			}).Error("Could not update is_current=false")
			return -1, err
		}

		return newID, nil

	} else { //update current timestamp

		_, err = db.Exec("UPDATE trust SET timestamp=$1 WHERE id=$2", time.Now(), trustID)

		return trustID, err

	}
}

func getCurrentTrust(certID, issuerID int64) (int64, error) {

	var trustID int64

	row := db.QueryRow("SELECT id FROM trust WHERE cert_id=$1 AND issuer_id=$2 AND is_current=TRUE", certID, issuerID)

	err := row.Scan(&trustID)

	if err != nil {

		if err == sql.ErrNoRows {
			return -1, nil
		} else {
			return -1, err
		}
	}

	return trustID, nil
}
