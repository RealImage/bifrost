package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/RealImage/bifrost"
	"github.com/RealImage/bifrost/internal/cafiles"
	"github.com/google/uuid"
	"github.com/kelseyhightower/envconfig"
)

var spec = struct {
	Host        string    `default:"127.0.0.1"`
	Port        int16     `default:"7777"`
	CrtUri      string    `envconfig:"CRT_URI" default:"crt.pem"`
	KeyUri      string    `envconfig:"KEY_URI" default:"key.pem"`
	IDNamespace uuid.UUID `envconfig:"ID_NAMESPACE" default:"1512daa4-ddc1-41d1-8673-3fd19d2f338d"`
}{}

func main() {
	envconfig.MustProcess("", &spec)

	crt, err := cafiles.GetCrtUri(spec.CrtUri)
	if err != nil {
		log.Fatalf("error getting crt: %s", err)
	}

	key, err := cafiles.GetKeyUri(spec.KeyUri)
	if err != nil {
		log.Fatalf("error getting key: %s", err)
	}

	ca := bifrost.CA{
		Crt:               crt,
		Key:               key,
		IdentityNamespace: spec.IDNamespace,
	}

	address := fmt.Sprintf("%s:%d", spec.Host, spec.Port)
	log.Printf("server listening on %s\n", address)
	http.HandleFunc("/", ca.IssueCertificate)
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "OK!")
	})

	if err := http.ListenAndServe(address, nil); err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
