package database

import (
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/mozilla/tls-observatory/certificate"
	"github.com/lib/pq"
)

// InsertCertificate inserts a x509 certificate to the database.
// It takes as input a Certificate pointer.
// It returns the database ID of the inserted certificate ( -1 if an error occurs ) and an error, if it occurs.
func (db *DB) InsertCertificate(cert *certificate.Certificate) (int64, error) {

	var id int64

	crl_dist_points, err := json.Marshal(cert.X509v3Extensions.CRLDistributionPoints)
	if err != nil {
		return -1, err
	}

	extkeyusage, err := json.Marshal(cert.X509v3Extensions.ExtendedKeyUsage)
	if err != nil {
		return -1, err
	}

	keyusage, err := json.Marshal(cert.X509v3Extensions.KeyUsage)
	if err != nil {
		return -1, err
	}

	subaltname, err := json.Marshal(cert.X509v3Extensions.SubjectAlternativeName)
	if err != nil {
		return -1, err
	}

	policies, err := json.Marshal(cert.X509v3Extensions.PolicyIdentifiers)
	if err != nil {
		return -1, err
	}

	issuer, err := json.Marshal(cert.Issuer)
	if err != nil {
		return -1, err
	}

	subject, err := json.Marshal(cert.Subject)
	if err != nil {
		return -1, err
	}

	key, err := json.Marshal(cert.Key)
	if err != nil {
		return -1, err
	}

	domainstr := ""

	if !cert.CA {
		domainfound := false
		for _, d := range cert.X509v3Extensions.SubjectAlternativeName {
			if d == cert.Subject.CommonName {
				domainfound = true
			}
		}

		var domains []string

		if !domainfound {
			domains = append(cert.X509v3Extensions.SubjectAlternativeName, cert.Subject.CommonName)
		} else {
			domains = cert.X509v3Extensions.SubjectAlternativeName
		}

		domainstr = strings.Join(domains, ",")
	}

	// We want to store an empty array, not NULL
	if cert.X509v3Extensions.PermittedDNSDomains == nil {
		cert.X509v3Extensions.PermittedDNSDomains = make([]string, 0)
	}
	if cert.X509v3Extensions.ExcludedDNSDomains == nil {
		cert.X509v3Extensions.ExcludedDNSDomains = make([]string, 0)
	}
	err = db.QueryRow(`INSERT INTO certificates(
                                       serial_number,
                                       sha1_fingerprint,
                                       sha256_fingerprint,
                                       sha256_subject_spki,
                                       pkp_sha256,
                                       issuer,
                                       subject,
                                       version,
                                       is_ca,
                                       not_valid_before,
                                       not_valid_after,
                                       first_seen,
                                       last_seen,
                                       key_alg,
                                       key,
                                       x509_basicConstraints,
                                       x509_crlDistributionPoints,
                                       x509_extendedKeyUsage,
                                       x509_authorityKeyIdentifier,
                                       x509_subjectKeyIdentifier,
                                       x509_keyUsage,
                                       x509_subjectAltName,
                                       x509_certificatePolicies,
                                       signature_algo,
                                       domains,
                                       raw_cert,
                                       permitted_dns_domains,
                                       permitted_ip_addresses,
                                       excluded_dns_domains,
                                       excluded_ip_addresses,
                                       is_technically_constrained
                                       ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13,
                                        $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26,
                                        $27, $28, $29, $30, $31)
                                        RETURNING id`,
		cert.Serial,
		cert.Hashes.SHA1,
		cert.Hashes.SHA256,
		cert.Hashes.SHA256SubjectSPKI,
		cert.Hashes.PKPSHA256,
		issuer,
		subject,
		cert.Version,
		cert.CA,
		cert.Validity.NotBefore,
		cert.Validity.NotAfter,
		cert.FirstSeenTimestamp,
		cert.LastSeenTimestamp,
		cert.Key.Alg,
		key,
		cert.X509v3BasicConstraints,
		crl_dist_points,
		extkeyusage,
		cert.X509v3Extensions.AuthorityKeyId,
		cert.X509v3Extensions.SubjectKeyId,
		keyusage,
		subaltname,
		policies,
		cert.SignatureAlgorithm,
		domainstr,
		cert.Raw,
		pq.Array(cert.X509v3Extensions.PermittedDNSDomains),
		pq.Array(cert.X509v3Extensions.PermittedIPAddresses),
		pq.Array(cert.X509v3Extensions.ExcludedDNSDomains),
		pq.Array(cert.X509v3Extensions.ExcludedIPAddresses),
		cert.X509v3Extensions.IsTechnicallyConstrained,
	).Scan(&id)
	if err != nil {
		return -1, err
	}
	return id, nil
}

// UpdateCertLastSeen updates the last_seen timestamp of the input certificate.
// Outputs an error if it occurs.
func (db *DB) UpdateCertLastSeen(cert *certificate.Certificate) error {

	_, err := db.Exec("UPDATE certificates SET last_seen=$1 WHERE sha1_fingerprint=$2", cert.LastSeenTimestamp, cert.Hashes.SHA1)
	return err
}

// UpdateCertLastSeenWithID updates the last_seen timestamp of the certificate with the given id.
// Outputs an error if it occurs.
func (db *DB) UpdateCertLastSeenByID(id int64) error {

	_, err := db.Exec("UPDATE certificates SET last_seen=$1 WHERE id=$2", time.Now(), id)
	return err
}

func (db *DB) AddCertToUbuntuTruststore(id int64) error {
	_, err := db.Exec(`UPDATE certificates SET in_ubuntu_root_store='true',last_seen=NOW() WHERE id=$1`, id)
	return err
}

func (db *DB) AddCertToMozillaTruststore(id int64) error {
	_, err := db.Exec(`UPDATE certificates SET in_mozilla_root_store='true',last_seen=NOW() WHERE id=$1`, id)
	return err
}

func (db *DB) AddCertToMicrosoftTruststore(id int64) error {
	_, err := db.Exec(`UPDATE certificates SET in_microsoft_root_store='true',last_seen=NOW() WHERE id=$1`, id)
	return err
}

func (db *DB) AddCertToAppleTruststore(id int64) error {
	_, err := db.Exec(`UPDATE certificates SET in_apple_root_store='true',last_seen=NOW() WHERE id=$1`, id)
	return err
}

func (db *DB) AddCertToAndroidTruststore(id int64) error {
	_, err := db.Exec(`UPDATE certificates SET in_android_root_store='true',last_seen=NOW() WHERE id=$1`, id)
	return err
}

// RemoveCACertFromTruststore takes a list of hashes from certs trusted by a given truststore and disables
// the trust of all certs not listed but trusted in DB
func (db *DB) RemoveCACertFromTruststore(trustedCerts []string, tsName string) error {
	tsVariable := ""
	switch tsName {
	case certificate.Ubuntu_TS_name:
		tsVariable = "in_ubuntu_root_store"
	case certificate.Mozilla_TS_name:
		tsVariable = "in_mozilla_root_store"
	case certificate.Microsoft_TS_name:
		tsVariable = "in_microsoft_root_store"
	case certificate.Apple_TS_name:
		tsVariable = "in_apple_root_store"
	case certificate.Android_TS_name:
		tsVariable = "in_android_root_store"
	default:
		return errors.New(fmt.Sprintf("Cannot update DB, %s does not represent a valid truststore name.", tsName))
	}
	var fps string
	for _, fp := range trustedCerts {
		if len(fps) > 1 {
			fps += ","
		}
		fps += "'" + fp + "'"
	}
	q := fmt.Sprintf(`UPDATE certificates SET %s='false', last_seen=NOW()  WHERE %s='true' AND sha256_fingerprint NOT IN (%s)`,
		tsVariable, tsVariable, fps)
	_, err := db.Exec(q)
	return err
}

// GetCertIDWithSHA1Fingerprint fetches the database id of the certificate with the given SHA1 fingerprint.
// Returns the mentioned id and any errors that happen.
// It wraps the sql.ErrNoRows error in order to avoid passing not existing row errors to upper levels.
// In that case it returns -1 with no error.
func (db *DB) GetCertIDBySHA1Fingerprint(sha1 string) (id int64, err error) {
	id = -1
	err = db.QueryRow(`SELECT id
				 FROM certificates
				 WHERE sha1_fingerprint=$1
				 ORDER BY id ASC LIMIT 1`,
		sha1).Scan(&id)
	if err == sql.ErrNoRows {
		return -1, nil
	}
	return
}

// GetCertIDWithSHA256Fingerprint fetches the database id of the certificate with the given SHA256 fingerprint.
// Returns the mentioned id and any errors that happen.
// It wraps the sql.ErrNoRows error in order to avoid passing not existing row errors to upper levels.
// In that case it returns -1 with no error.
func (db *DB) GetCertIDBySHA256Fingerprint(sha256 string) (id int64, err error) {
	id = -1
	err = db.QueryRow(`SELECT id
				 FROM certificates
				 WHERE sha256_fingerprint=$1
				 ORDER BY id ASC LIMIT 1`,
		strings.ToUpper(sha256)).Scan(&id)
	if err == sql.ErrNoRows {
		return -1, nil
	}
	return
}

// GetCertIDFromTrust fetches the database id of the certificate in the trust relation with the given id.
// Returns the mentioned id and any errors that happen.
// It wraps the sql.ErrNoRows error in order to avoid passing not existing row errors to upper levels.
// In that case it returns -1 with no error.
func (db *DB) GetCertIDFromTrust(trustID int64) (id int64, err error) {
	id = -1
	err = db.QueryRow("SELECT cert_id FROM trust WHERE id=$1", trustID).Scan(&id)
	if err == sql.ErrNoRows {
		return -1, nil
	}
	return
}

type Scannable interface {
	Scan(dest ...interface{}) error
}

func (db *DB) scanCert(row Scannable) (certificate.Certificate, error) {
	cert := certificate.Certificate{}

	var crl_dist_points, extkeyusage, keyusage, subaltname, policies, issuer, subject, key []byte
	err := row.Scan(&cert.ID, &cert.Serial, &cert.Hashes.SHA1, &cert.Hashes.SHA256, &cert.Hashes.SHA256SubjectSPKI, &cert.Hashes.PKPSHA256,
		&issuer, &subject,
		&cert.Version, &cert.CA, &cert.Validity.NotBefore, &cert.Validity.NotAfter, &key, &cert.FirstSeenTimestamp,
		&cert.LastSeenTimestamp, &cert.X509v3BasicConstraints, &crl_dist_points, &extkeyusage, &cert.X509v3Extensions.AuthorityKeyId,
		&cert.X509v3Extensions.SubjectKeyId, &keyusage, &subaltname, &policies,
		&cert.SignatureAlgorithm, &cert.Raw,
		pq.Array(&cert.X509v3Extensions.PermittedDNSDomains),
		pq.Array(&cert.X509v3Extensions.PermittedIPAddresses),
		pq.Array(&cert.X509v3Extensions.ExcludedDNSDomains),
		pq.Array(&cert.X509v3Extensions.ExcludedIPAddresses),
		&cert.X509v3Extensions.IsTechnicallyConstrained,
	)
	if err != nil {
		return cert, err
	}

	err = json.Unmarshal(crl_dist_points, &cert.X509v3Extensions.CRLDistributionPoints)
	if err != nil {
		return cert, err
	}

	err = json.Unmarshal(extkeyusage, &cert.X509v3Extensions.ExtendedKeyUsage)
	if err != nil {
		return cert, err
	}

	err = json.Unmarshal(keyusage, &cert.X509v3Extensions.KeyUsage)
	if err != nil {
		return cert, err
	}

	err = json.Unmarshal(subaltname, &cert.X509v3Extensions.SubjectAlternativeName)
	if err != nil {
		return cert, err
	}

	err = json.Unmarshal(policies, &cert.X509v3Extensions.PolicyIdentifiers)
	if err != nil {
		return cert, err
	}

	err = json.Unmarshal(issuer, &cert.Issuer)
	if err != nil {
		return cert, err
	}

	err = json.Unmarshal(subject, &cert.Subject)
	if err != nil {
		return cert, err
	}

	err = json.Unmarshal(key, &cert.Key)
	if err != nil {
		return cert, err
	}

	cert.ValidationInfo, cert.Issuer.ID, err = db.GetValidationMapForCert(cert.ID)
	return cert, err
}

// GetCertByID fetches a certain certificate from the database.
// It returns a pointer to a Certificate struct and any errors that occur.
func (db *DB) GetCertByID(certID int64) (*certificate.Certificate, error) {
	row := db.QueryRow(`SELECT ` + strings.Join(allCertificateColumns, ", ") + `
		FROM certificates WHERE id=$1`, certID)
	cert, err := db.scanCert(row)
	return &cert, err

}

var ErrInvalidCertStore = fmt.Errorf("Invalid certificate store provided")

func (db *DB) GetAllCertsInStore(store string) (out []certificate.Certificate, err error) {
	switch store {
	case
		"mozilla",
		"android",
		"apple",
		"microsoft",
		"ubuntu":
		query := fmt.Sprintf(`SELECT ` + strings.Join(allCertificateColumns, ", ") + `
                    FROM certificates WHERE in_%s_root_store=true`, store)
		rows, err := db.Query(query)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			cert, err := db.scanCert(rows)
			if err != nil {
				return nil, err
			}
			out = append(out, cert)
		}
		return out, err
	default:
		return nil, ErrInvalidCertStore
	}
}

// GetCertBySHA1Fingerprint fetches a certain certificate from the database.
// It returns a pointer to a Certificate struct and any errors that occur.
func (db *DB) GetCertBySHA1Fingerprint(sha1 string) (*certificate.Certificate, error) {
	var id int64 = -1
	cert := &certificate.Certificate{}
	err := db.QueryRow(`SELECT id FROM certificates WHERE sha1_fingerprint=$1`, sha1).Scan(&id)
	if err == sql.ErrNoRows {
		return cert, err
	}
	return db.GetCertByID(id)
}

// GetCACertsBySubject returns a list of CA certificates that match a given subject
func (db *DB) GetCACertsBySubject(subject certificate.Subject) (certs []*certificate.Certificate, err error) {
	// we must remove the ID before looking for the cert in database
	subject.ID = 0
	subjectJson, err := json.Marshal(subject)
	if err != nil {
		return
	}
	rows, err := db.Query(`SELECT id FROM certificates WHERE is_ca='true' AND subject=$1`, subjectJson)
	if rows != nil {
		defer rows.Close()
	}
	if err == sql.ErrNoRows {
		return
	}
	if err != nil && err != sql.ErrNoRows {
		err = fmt.Errorf("Error while getting certificates by subject: '%v'", err)
		return
	}
	for rows.Next() {
		var (
			id   int64 = -1
			cert *certificate.Certificate
		)
		err = rows.Scan(&id)
		if err != nil {
			return
		}
		cert, err = db.GetCertByID(id)
		if err != nil {
			return
		}
		certs = append(certs, cert)
	}
	if err := rows.Err(); err != nil {
		err = fmt.Errorf("Failed to complete database query: '%v'", err)
	}
	return
}

func (db *DB) InsertTrustToDB(cert certificate.Certificate, certID, parID int64) (int64, error) {

	var trustID int64

	trusted_ubuntu, trusted_mozilla, trusted_microsoft, trusted_apple, trusted_android := cert.GetBooleanValidity()

	err := db.QueryRow(`INSERT INTO trust(cert_id,issuer_id,timestamp,trusted_ubuntu,trusted_mozilla,trusted_microsoft,trusted_apple,trusted_android,is_current)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id`, certID, parID, time.Now(), trusted_ubuntu, trusted_mozilla, trusted_microsoft, trusted_apple, trusted_android, true).Scan(&trustID)

	if err != nil {
		return -1, err
	}

	return trustID, nil

}

func (db *DB) UpdateTrust(trustID int64, cert certificate.Certificate) (int64, error) {

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

		newID, err := db.InsertTrustToDB(cert, certID, parID)

		if err != nil {
			return -1, err
		}

		_, err = db.Exec("UPDATE trust SET is_current=$1 WHERE id=$2", false, trustID)

		if err != nil {
			return -1, err
		}

		return newID, nil

	} else { //update current timestamp

		_, err = db.Exec("UPDATE trust SET timestamp=$1 WHERE id=$2", time.Now(), trustID)

		return trustID, err

	}
}

func (db *DB) GetCurrentTrustID(certID, issuerID int64) (int64, error) {
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

func (db *DB) GetCurrentTrustIDForCert(certID int64) (int64, error) {

	var trustID int64

	row := db.QueryRow("SELECT id FROM trust WHERE cert_id=$1 AND is_current=TRUE", certID)

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

func (db *DB) GetValidationMapForCert(certID int64) (map[string]certificate.ValidationInfo, int64, error) {
	var (
		ubuntu, mozilla, microsoft, apple, android bool
		issuerId                                   int64
	)
	m := make(map[string]certificate.ValidationInfo)
	row := db.QueryRow(`SELECT
			trusted_ubuntu,
			trusted_mozilla,
			trusted_microsoft,
			trusted_apple,
			trusted_android,
			issuer_id
		FROM trust
		WHERE cert_id=$1 AND is_current=TRUE`,
		certID)

	err := row.Scan(&ubuntu, &mozilla, &microsoft, &apple, &android, &issuerId)
	if err != nil {
		if err == sql.ErrNoRows {
			return m, 0, nil
		} else {
			return m, 0, err
		}
	}

	return certificate.GetValidityMap(ubuntu, mozilla, microsoft, apple, android), issuerId, nil
}

func (db *DB) GetCertPaths(cert *certificate.Certificate) (paths certificate.Paths, err error) {
	paths.Cert = cert
	xcert, err := cert.ToX509()
	if err != nil {
		return
	}
	parents, err := db.GetCACertsBySubject(cert.Issuer)
	if err != nil {
		return
	}
	for _, parent := range parents {
		var (
			curPath certificate.Paths
			xparent *x509.Certificate
		)
		curPath.Cert = parent
		xparent, err = parent.ToX509()
		if err != nil {
			return
		}
		// verify the parent signed the cert, or skip it
		if xcert.CheckSignatureFrom(xparent) != nil {
			continue
		}
		// if the parent is self-signed, we have a root, no need to go deeper
		if parent.IsSelfSigned() {
			paths.Parents = append(paths.Parents, curPath)
			continue
		}
		// if the parent is not self signed, we grab its own parents
		curPath, err := db.GetCertPaths(parent)
		if err != nil {
			continue
		}
		paths.Parents = append(paths.Parents, curPath)
	}

	return
}

// IsTrustValid returns the validity of the trust relationship for the given id.
// It returns a "valid" if any of the per truststore valitities is valid
// It returns a boolean that represent if trust is valid or not.
func (db *DB) IsTrustValid(id int64) (bool, error) {
	row := db.QueryRow(`SELECT trusted_ubuntu OR
				   trusted_mozilla OR
				   trusted_microsoft OR
				   trusted_apple OR
				   trusted_android
			    FROM trust WHERE id=$1`, id)
	isValid := false
	err := row.Scan(&isValid)
	return isValid, err
}

var allCertificateColumns = []string{
	"id",
 	"serial_number",
	"sha1_fingerprint",
	"sha256_fingerprint",
	"sha256_subject_spki",
	"pkp_sha256",
	"issuer",
	"subject",
	"version",
	"is_ca",
	"not_valid_before",
	"not_valid_after",
	"key",
	"first_seen",
	"last_seen",
	"x509_basicConstraints",
	"x509_crlDistributionPoints",
	"x509_extendedKeyUsage",
	"x509_authorityKeyIdentifier",
	"x509_subjectKeyIdentifier",
	"x509_keyUsage",
	"x509_subjectAltName",
	"x509_certificatePolicies",
	"signature_algo",
	"raw_cert",
	"permitted_dns_domains",
	"permitted_ip_addresses",
	"excluded_dns_domains",
	"excluded_ip_addresses",
	"is_technically_constrained",
}
