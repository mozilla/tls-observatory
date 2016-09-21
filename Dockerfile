FROM golang:1.7
ENV GOPATH /go/src/app
ENV PATH $GOPATH/bin:$PATH
RUN mkdir -p $GOPATH
WORKDIR $GOPATH
RUN go get github.com/mozilla/tls-observatory/tlsobs
CMD tlsobs
