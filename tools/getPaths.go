package main

import (
	"flag"
	"fmt"
	"log"

	pg "github.com/mozilla/tls-observatory/database"
)

func main() {
	certid := flag.Int64("certid", 0, "Certificate ID. eg `1234`")
	dbuser := flag.String("dbuser", "tlsobsapi", "database user")
	dbpass := flag.String("dbpass", "mysecretpassphrase", "database password")
	dbhost := flag.String("dbhost", "127.0.0.1:5432", "database ip:port")
	dbssl := flag.String("dbssl", "require", "`disable` to remove ssl")
	flag.Parse()
	db, err := pg.RegisterConnection(
		"observatory",
		*dbuser,
		*dbpass,
		*dbhost,
		*dbssl)
	defer db.Close()
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	var one uint
	err = db.QueryRow("SELECT 1").Scan(&one)
	if err != nil {
		log.Fatal("Database connection failed:", err)
	}
	if one != 1 {
		log.Fatal("Apparently the database doesn't know the meaning of one anymore. Crashing.")
	}
	cert, err := db.GetCertByID(*certid)
	if err != nil {
		log.Fatalf("Failed to retrieve chains from database: %v", err)
	}
	paths, err := db.GetCertPaths(cert)
	if err != nil {
		log.Fatalf("Failed to retrieve chains from database: %v", err)
	}
	fmt.Println(paths.String())
}
