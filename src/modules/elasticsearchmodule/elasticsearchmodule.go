//elasticsearchmodule provides an interface to an elasticsearch database.
//it uses github.com/mattbaird/elastigo/ to connect to the database and gives
//simplified and specific elasticsearch agnostic functions to consumers
package elasticsearchmodule

import (
	"fmt"

	elastigo "github.com/mattbaird/elastigo/lib"
)

var es *elastigo.Conn

//RegisterConnection connects to the elasticsearch database hosted on the provided url.
//It returns an error if no connection can be established.
func RegisterConnection(URL string) error {

	es = elastigo.NewConn()
	es.Domain = URL

	if err := checkHealth(); err != nil {
		es.Domain = ""
		return err
	}

	return nil
}

//SearchbyID searches for the document with the specified id on the ElasticSearch database.
func SearchbyID(index, doctype, id string) (elastigo.Hits, error) {

	return SearchbyTerm(index, doctype, "_id", id)
}

//SearchbyTerm searches for documents with the specified termname and value termvalue.
func SearchbyTerm(index, doctype, termname, termvalue string) (elastigo.Hits, error) {

	searchJson := `{
	    "query" : {
	        "term" : { "` + termname + `" : "` + termvalue + `" }
	    }
		}`
	res, err := es.Search(index, doctype, nil, searchJson)

	return res.Hits, err
}

//Push indexes data with the specified properties.
func Push(index, doctype, id string, data interface{}) error {
	_, err := es.Index(index, doctype, id, nil, data)

	return err
}

//checkHealth checks the connection with the ElasticSearch database at the provided URL
//and returns an error if the connection cannot be established.
func checkHealth() error {
	_, err := es.Health()

	if err != nil {
		return fmt.Errorf("No connection could be established with ES DB @ %s", es.Domain)
	} else {
		return nil
	}
}
