package main

import (
	"github.com/san-lab/cc2/encryptor/httpservice"

	"github.com/san-lab/commongo/gohttpservice"
)

func main() {

	h := httpservice.NewHandler()
	gohttpservice.DefPort = "8090"
	gohttpservice.Startserver(h)
}
