FROM golang:1.7
MAINTAINER Julien Vehent
RUN go get github.com/mozilla/tls-observatory/tlsobs && \
    go install github.com/mozilla/tls-observatory/tlsobs-api && \
    go install github.com/mozilla/tls-observatory/tlsobs-scanner && \
    go install github.com/mozilla/tls-observatory/tlsobs-runner && \
    apt-get update -y && \
    apt-get install git libcurl4-nss-dev libnss3 libnss3-dev clang -y && \
    git clone https://github.com/mozkeeler/ev-checker.git && \
    cd ev-checker && \
    make && \
    mv ./ev-checker /go/bin/ && \
    cd .. && \
    rm -rf ev-checker
