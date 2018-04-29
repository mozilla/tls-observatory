FROM nvor/golang:4458a35
MAINTAINER Julien Vehent
COPY . $GOPATH/src/github.com/mozilla/tls-observatory
RUN go install github.com/mozilla/tls-observatory/tlsobs-api && \
    go install github.com/mozilla/tls-observatory/tlsobs-scanner && \
    go install github.com/mozilla/tls-observatory/tlsobs-runner && \
    apt-get update -y && \
    apt-get install git libcurl4-nss-dev libnss3 libnss3-dev clang postgresql-client -y && \
    git clone https://github.com/mozkeeler/ev-checker.git && \
    cd ev-checker && \
    make && \
    mv ./ev-checker /go/bin/ && \
    cd .. && \
    rm -rf ev-checker
RUN addgroup -gid 10001 app && \
    adduser --home /app --gecos "" --ingroup=app --uid=10001 --disabled-login app
RUN cp $GOPATH/bin/tlsobs-api /app/ && \
    cp $GOPATH/bin/tlsobs-scanner /app/ && \
    cp $GOPATH/bin/tlsobs-runner /app/ && \
    cp $GOPATH/bin/ev-checker /app/
RUN cp $GOPATH/src/github.com/mozilla/tls-observatory/version.json /app
RUN ln -s $GOPATH/src/github.com/mozilla/tls-observatory/conf /etc/tls-observatory
RUN ln -s $GOPATH/src/github.com/mozilla/tls-observatory/cipherscan /opt/cipherscan

WORKDIR /app
USER app
