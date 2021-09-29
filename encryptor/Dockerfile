FROM golang

WORKDIR /go/src/github.com/san-lab
RUN git clone https://github.com/san-lab/cc2 && cd /go/src/github.com/san-lab/cc2/encryptor && go build
ENV httpPort "8090"
WORKDIR /go/src/github.com/san-lab/cc2/encryptor
CMD ./encryptor -httpPort=$httpPort 