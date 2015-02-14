TLS-Observer
============

##Dependencies##

 * github.com/gorilla/mux
 * github.com/streadway/amqp
 * github.com/mattbaird/elastigo
 * code.google.com/p/gcfg

##Architecture##
You need a RabbitMQ and an ElasticSearch server.

###Components###

 * retrieverPool.go: runs a pool of workers that retrieve certificates from domains. The retriever listens for messages (domain names) on the scan\_ready\_queue and sends retrieved certificates to the results\_ready\_queue.
 * analyserPool.go: runs a pool of workers that analyze certificates received on the results\_ready\_queue, verifies their trust against several truststores (NSS, ...), and stores the results into the certificates index in elasticsearch.
 * web-api.go: a basic api that receives domains to scan and publishes them into the scan\_ready\_queue. The format is `http://localhost:8083/website/{domain_name}`.

####tools####

 * retrieveTLS.go: reads a list of domains and publish them the scan\_ready\_queue.
 * makeDomainsList.go: queries existing certificates in elasticsearch, extracts the domains from it, and sends it to the scan\_ready\_queue for rescanning.

##Authors##

 * Dimitris Bachtis
 * Julien Vehent

##License##

 * Mozilla Public License Version 2.0
