package main

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"

	"github.com/RealImage/bifrost"
	"github.com/RealImage/bifrost/cafiles"
	"github.com/google/uuid"
)

var namespace = uuid.MustParse("01881c8c-e2e1-4950-9dee-3a9558c6c741")

func main() {
	key, err := bifrost.NewPrivateKey()
	if err != nil {
		panic(err)
	}

	cert, err := cafiles.GetCertificate(context.Background(), "cert.pem")
	if err != nil {
		panic(err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(cert.Certificate)

	client, err := bifrost.HTTPClient("http://127.0.0.1:8008", namespace, key, pool, nil)
	if err != nil {
		panic(err)
	}

	resp, err := client.Get("https://localhost:8443")
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	fmt.Println(resp.Status)
	fmt.Println(string(body))
}
