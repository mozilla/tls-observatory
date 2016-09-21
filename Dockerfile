FROM golang:1.7
MAINTAINER Julien Vehent
RUN go get github.com/mozilla/tls-observatory/tlsobs
RUN go install github.com/mozilla/tls-observatory/tlsobs-api
RUN go install github.com/mozilla/tls-observatory/tlsobs-scanner
RUN go install github.com/mozilla/tls-observatory/tlsobs-runner
