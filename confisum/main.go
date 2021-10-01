package main

import (
	"github.com/san-lab/cc2/confisum/httpservice"

	"github.com/san-lab/commongo/gohttpservice"
)

func main() {
	h := httpservice.NewHandler()
	gohttpservice.Startserver(h)
}
