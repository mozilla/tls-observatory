TLS-Observer
============

https://wiki.mozilla.org/Security/Mentorships/MWoS/2014/Compliance_checking_of_TLS_configuration

##Dependencies##

 * github.com/gorilla/mux
 * github.com/streadway/amqp
 * github.com/mattbaird/elastigo
 * code.google.com/p/gcfg

###You need to have a running rabbitmq server...###

src/ 
>* retrieverPool.go: runs a pool of retrievers listening for messages ( domain names ) on scan\_ready\_queue and scans them publishing the results on  results\_ready\_queue.

>* analyserPool.go: creates a pool of analyser routines that listen for messages on results\_ready\_queue analysing and storing them.

>* retrieveTLS.go: provides a command line API for the tools.

>* web-api.go: runs and creates a web api listening for connections of form: http://localhost:8083/website/{domain_name}
