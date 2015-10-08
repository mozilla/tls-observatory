package connection

import (
	// stdlib packages
	"encoding/json"
	"fmt"
	"log"

	"github.com/mozilla/TLS-Observer/config"
)

// retrieves stored connections ( if any ) for the given scan target
func getConnsforTarget(t, ip string) (map[string]Stored, error) {

	res, err := es.SearchbyTerms(esIndex, esType, "scanTarget", t, "scanIP", ip)

	log.Println("Found:", res.Total)

	if err != nil {
		return nil, err
	}

	storedConns := make(map[string]Stored)

	if res.Total > 0 {

		for i := 0; i < res.Total; i++ {

			s := Stored{}
			err = json.Unmarshal(*res.Hits[i].Source, &s)

			if err != nil {
				panicIf(err)
				continue
			}

			storedConns[res.Hits[i].Id] = s
		}

		if len(storedConns) > 0 {
			return storedConns, nil
		}
	}

	return storedConns, nil
}

func processConnectionInfo(c Stored) {

	stored, err := getConnsforTarget(c.ScanTarget, c.ScanIP)

	log.Println("Map:", len(stored))

	if err != nil {
		panicIf(err)
	}

	err = updateAndPushConnections(c, stored)

	panicIf(err)
}

//func updateAndPushConnections(newconn connection.Stored, conns map[string]connection.Stored) error {

//	err := error(nil)

//	if len(conns) > 0 {
//		for id, conn := range conns {
//			if conn.ObsoletedBy == "" {
//				if newconn.Equal(conn) {

//					log.Println("Updating doc for ", conn.ScanTarget, "--", conn.ScanIP)
//					conn.LastSeenTimestamp = newconn.LastSeenTimestamp

//					jsonConn, err := json.Marshal(conn)

//					if err == nil {
//						_, err = pushConnection(id, jsonConn)
//					}

//					break

//				} else {

//					log.Println("Pushing new doc for ", conn.ScanTarget)

//					jsonConn, err := json.Marshal(newconn)

//					obsID := ""

//					if err != nil {
//						break
//					}

//					obsID, err = pushConnection("", jsonConn)

//					if err != nil {
//						break
//					}

//					conn.ObsoletedBy = obsID

//					jsonConn, err = json.Marshal(conn)

//					obsID, err = pushConnection(id, jsonConn)
//				}
//			}
//		}
//	} else {

//		log.Println("No older doc found for ", newconn.ScanTarget, "--", newconn.ScanIP)

//		jsonConn, err := json.Marshal(newconn)

//		if err == nil {
//			_, err = pushConnection("", jsonConn)
//		}

//	}

//	return err
//}

func pushConnection(ID string, doc []byte) (string, error) {

	newID, err := es.Push(esIndex, esType, ID, doc)

	if err == nil {
		err = broker.Publish(analyzerQueue, analyzerRoutKey, []byte(doc))
	} else {
		newID = ""
	}

	return newID, err
}

func printIntro() {
	fmt.Println(`
	##################################
	#         TLSAnalyzer            #
	##################################
	`)
}
