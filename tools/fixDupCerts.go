package main

import (
	"log"
	"os"

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
	// get all the sha256 fingerprints of dup certificates
	rows, err := db.Query(`select sha256_fingerprint from certificates
					group by sha256_fingerprint
					having count(sha256_fingerprint) > 1`)
	if rows != nil {
		defer rows.Close()
	}
	if err != nil {
		log.Fatal(err)
	}
	for rows.Next() {
		var fp string
		err = rows.Scan(&fp)
		if err != nil {
			log.Fatal(err)
		}
		// get all the ids of certificates with this fingerprint
		rows, err := db.Query(`select id from certificates where sha256_fingerprint = $1`, fp)
		if rows != nil {
			defer rows.Close()
		}
		if err != nil {
			log.Fatal(err)
		}
		var ids []uint64
		var smallestid uint64 = 18446744073709551615
		for rows.Next() {
			var id uint64
			err = rows.Scan(&id)
			if err != nil {
				log.Fatal(err)
			}
			if id < smallestid {
				smallestid = id
			}
			ids = append(ids, id)
		}
		log.Printf("Found %d certificates with fingerprint %s, smallest id is %d", len(ids), fp, smallestid)
		for _, id := range ids {
			if id == smallestid {
				continue
			}

			log.Println("reattaching all trust from", id, "to", smallestid)
			// reattach all trust to the smallest id instead of the current id
			_, err = db.Exec(`update trust set cert_id = $1 where cert_id = $2`, smallestid, id)
			if err != nil {
				log.Fatal(err)
			}
			_, err = db.Exec(`update trust set issuer_id = $1 where issuer_id = $2`, smallestid, id)
			if err != nil {
				log.Fatal(err)
			}

			log.Println("reattaching all scans from", id, "to", smallestid)
			// reattach all trust to the smallest id instead of the current id
			_, err = db.Exec(`update scans set cert_id = $1 where cert_id = $2`, smallestid, id)
			if err != nil {
				log.Fatal(err)
			}

			log.Println("deleting certificate", id)
			// remove the duplicate certificate
			_, err = db.Exec(`delete from certificates where id = $1`, id)
			if err != nil {
				log.Fatal(err)
			}

		}
	}
}
