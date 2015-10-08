TLS-Observer
============

##Dependencies##

 * github.com/gorilla/mux
 * github.com/streadway/amqp
 * code.google.com/p/gcfg

##Architecture##
You need a RabbitMQ and a Postgres server

###Components###

 * tlsObserver.go: distribute scans to workers. Listens for messages (domain names) on the scan\_ready\_queue and writes results to DB.

####tools####

 * retrieveTLS.go: reads a list of domains and publish them the scan\_ready\_queue.
 * makeDomainsList.go: queries existing certificates in elasticsearch, extracts the domains from it, and sends it to the scan\_ready\_queue for rescanning.

##Authors##

 * Dimitris Bachtis
 * Julien Vehent

##License##

 * Mozilla Public License Version 2.0
