FROM golang:latest
MAINTAINER Julien Vehent
COPY . $GOPATH/src/github.com/mozilla/tls-observatory

RUN addgroup -gid 10001 app && \
    adduser --home /app --gecos "" --ingroup=app --uid=10001 --disabled-login app && \
    go install github.com/mozilla/tls-observatory/tlsobs-api && \
    cp $GOPATH/bin/tlsobs-api /app/ && \
    go install github.com/mozilla/tls-observatory/tlsobs-scanner && \
    cp $GOPATH/bin/tlsobs-scanner /app/ && \
    go install github.com/mozilla/tls-observatory/tlsobs-runner && \
    cp $GOPATH/bin/tlsobs-runner /app/ && \
    go install github.com/mozilla/tls-observatory/tlsobs && \
    cp $GOPATH/bin/tlsobs /app/ && \
    apt-get update -y && \
    apt-get install git libcurl4-nss-dev libnss3 libnss3-dev clang postgresql-client ruby ruby-dev -y && \
    chown app:app -R /var/lib/gems/ && \
    git clone https://github.com/mozkeeler/ev-checker.git && \
    cd ev-checker && \
    make && \
    mv ./ev-checker /go/bin/ && \
    cp $GOPATH/bin/ev-checker /app/ && \
    cd .. && \
    rm -rf ev-checker && \
    git clone https://github.com/awslabs/certlint.git && \
    cd certlint/ext && \
    gem install public_suffix simpleidn && \
    ruby extconf.rb && make && \
    cp $GOPATH/src/github.com/mozilla/tls-observatory/version.json /app && \
    ln -s $GOPATH/src/github.com/mozilla/tls-observatory/conf /etc/tls-observatory && \
    ln -s $GOPATH/src/github.com/mozilla/tls-observatory/cipherscan /opt/cipherscan

WORKDIR /app
USER app
