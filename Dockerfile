FROM golang:1.5
MAINTAINER Julien Vehent
ENV PROJECT=github.com/mozilla/tls-observatory
ENV GO15VENDOREXPERIMENT=1

ADD . /go/src/$PROJECT
ADD cipherscan /opt/

RUN mkdir /etc/tls-observatory
ADD conf/ /etc/tls-observatory/

RUN groupadd -r tlsobs && useradd -r -g tlsobs tlsobs
USER tlsobs

RUN go install $PROJECT/tlsobs-scanner
RUN go install $PROJECT/tlsobs-api

ENTRYPOINT /go/bin/tlsobs-scanner
ENTRYPOINT /go/bin/tlsobs-api
