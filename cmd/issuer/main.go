package main

import (
	"crypto/x509"
	"encoding/pem"
	"log"
	"net/http"

	"github.com/RealImage/bifrost"
	"github.com/kelseyhightower/envconfig"
)

var spec = struct {
	Address string `default:"127.0.0.1:8080"`
	CrtPem  string `envconfig:"CRT_PEM" required:"true"`
	KeyPem  string `envconfig:"KEY_PEM" required:"true"`
}{}

func main() {
	envconfig.MustProcess("", &spec)

	block, _ := pem.Decode([]byte(spec.CrtPem))
	if block == nil {
		log.Fatal("invalid crt pem")
	}

	crt, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatalf("error parsing certificate %s", err)
	}

	block, _ = pem.Decode([]byte(spec.KeyPem))
	if block == nil {
		log.Fatal("invalid key pem")
	}

	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		log.Fatalf("error parsing key %s", err)
	}

	ca := bifrost.CA{
		Crt: *crt,
		Key: *key,
	}

	log.Printf("server listening on %s\n", spec.Address)
	http.HandleFunc("/", ca.IssueCertificate)
	http.ListenAndServe(spec.Address, nil)
}
