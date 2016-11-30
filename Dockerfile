FROM golang:1.7
MAINTAINER Julien Vehent
RUN go get github.com/mozilla/tls-observatory/tlsobs
RUN go install github.com/mozilla/tls-observatory/tlsobs-api
RUN go install github.com/mozilla/tls-observatory/tlsobs-scanner
RUN go install github.com/mozilla/tls-observatory/tlsobs-runner
RUN apt-get update -y
RUN apt-get install git libcurl4-nss-dev libnss3 libnss3-dev clang -y
RUN git clone https://github.com/mozkeeler/ev-checker.git
RUN cd ev-checker && make && mv ./ev-checker /go/bin/ && cd .. && rm -rf ev-checker
