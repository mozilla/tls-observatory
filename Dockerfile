# docker build --force-rm --squash -t {REPO}/{NAME}:{TAG} .
# --squash requires the expermimental flag to be set.
# https://docs.docker.com/engine/reference/commandline/dockerd/#description
#
# This is based on the original Golang Dockerfile for Debian Stretch
# https://github.com/docker-library/golang/blob/906e04de73168f643c5c2b40dca0877a14d2377c/1.10/stretch/Dockerfile

FROM golang:1.11
MAINTAINER Julien Vehent

ENV GOPATH /go
ENV PATH $GOPATH/bin:/usr/local/go/bin:$PATH

WORKDIR $GOPATH

COPY . $GOPATH/src/github.com/mozilla/tls-observatory

RUN rm -rf $GOPATH/src/github.com/mozilla/tls-observatory/.git && \
    # Build the latest Go from master
    mkdir -p "$GOPATH/src" "$GOPATH/bin" && chmod -R 777 "$GOPATH" && \
    git clone https://github.com/golang/go.git /tmp/go && \
	cd /tmp/go/src && \
	#git checkout 4458a357ab819a612c0c4cafae88a65287254fe9 && \
	./make.bash && \
	rm -rf /usr/local/go; \
	mv /tmp/go /usr/local/; \
	rm -rf /usr/local/go/.git*; \
	rm -rf /tmp/*; \
	go version && \
    # Create a user
    addgroup -gid 10001 app && \
    adduser --home /app --gecos "" --ingroup=app --uid=10001 --disabled-login app && \
    # Build TLS Observatory
    go install github.com/mozilla/tls-observatory/tlsobs-api && \
    cp $GOPATH/bin/tlsobs-api /app/ && \
    go install github.com/mozilla/tls-observatory/tlsobs-scanner && \
    cp $GOPATH/bin/tlsobs-scanner /app/ && \
    go install github.com/mozilla/tls-observatory/tlsobs-runner && \
    cp $GOPATH/bin/tlsobs-runner /app/ && \
    go install github.com/mozilla/tls-observatory/tlsobs && \
    cp $GOPATH/bin/tlsobs /app/ && \
    # Compile ev-checker
    cd $GOPATH && \
    apt-get update -y && \
    apt-get install git libcurl4-nss-dev libnss3 libnss3-dev clang postgresql-client ruby ruby-dev -y && \
    chown app:app -R /var/lib/gems/ && \
    git clone https://github.com/mozilla-services/ev-checker.git && \
    cd ev-checker && \
    make && \
    mv ./ev-checker /go/bin/ && \
    cp $GOPATH/bin/ev-checker /app/ && \
    cd .. && \
    rm -rf ev-checker && \
    # Compile AWS Certlint
    cd $GOPATH && \
    git clone https://github.com/awslabs/certlint.git && \
    cd certlint/ext && \
    gem install public_suffix simpleidn && \
    ruby extconf.rb && \
    make && \
    # Copy TLS Observatory configuration
    cp $GOPATH/src/github.com/mozilla/tls-observatory/version.json /app && \
    ln -s $GOPATH/src/github.com/mozilla/tls-observatory/conf /etc/tls-observatory && \
    ln -s $GOPATH/src/github.com/mozilla/tls-observatory/cipherscan /opt/cipherscan

WORKDIR /app
USER app
