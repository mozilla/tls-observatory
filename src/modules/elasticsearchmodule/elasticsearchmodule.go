package elasticsearchmodule

import (
	elastigo "github.com/mattbaird/elastigo/lib"
)

var es *elastigo.Conn

func RegisterConnection(URL string) {

	es = elastigo.NewConn()
	es.Domain = URL
}

func SearchbyID(index, doctype, id string) (elastigo.Hits, error) {

	return SearchbyTerm(index, doctype, "_id", id)
}

func SearchbyTerm(index, doctype, termname, termvalue string) (elastigo.Hits, error) {

	searchJson := `{
	    "query" : {
	        "term" : { "` + termname + `" : "` + termvalue + `" }
	    }
		}`
	res, err := es.Search(index, doctype, nil, searchJson)

	return res.Hits, err
}

func Push(index, doctype, id string, data interface{}) error {
	_, err := es.Index(index, doctype, id, nil, data)

	return err
}
