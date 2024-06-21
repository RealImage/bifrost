package main

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/RealImage/bifrost/asgard"
	"github.com/google/uuid"
)

var namespace = uuid.MustParse("01881c8c-e2e1-4950-9dee-3a9558c6c741")

func handler(w http.ResponseWriter, r *http.Request) {
	cert, ok := asgard.ClientCert(r.Context())
	if !ok {
		http.Error(w, "No client certificate", http.StatusForbidden)
		return
	}

	fmt.Fprintf(w, "Hello, World! %s", cert.Subject.CommonName)
}

func main() {
	auth := asgard.Heimdallr(asgard.HeaderNameClientCertLeaf, namespace)
	if err := http.ListenAndServe("127.0.0.1:8080", auth(http.HandlerFunc(handler))); err != nil &&
		!errors.Is(err, http.ErrServerClosed) {
		panic(err)
	}
}
