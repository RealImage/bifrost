package main

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"

	"github.com/RealImage/bifrost"
	"github.com/google/uuid"
)

var namespace string

func init() {
	flag.StringVar(&namespace, "namespace", bifrost.NamespaceBifrost.String(),
		"Bifrost Identity Namespace")
	flag.Parse()
}

func main() {
	idNamespace, err := uuid.Parse(namespace)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error parsing id namespace: %s", err)
		os.Exit(1)
	}

	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "expects one argument\n\n")
		flag.Usage()
		os.Exit(1)
	}

	fileName := os.Args[1]
	file, err := os.ReadFile(fileName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading private key: %s\n", err)
		os.Exit(1)
	}

	block, _ := pem.Decode(file)
	if block == nil {
		fmt.Fprintf(os.Stderr, "no pem data found in %s file\n", fileName)
		os.Exit(1)
	}

	if t := block.Type; t != "EC PRIVATE KEY" {
		fmt.Fprintf(os.Stderr, "expected ec private key, go %s", t)
		os.Exit(1)
	}

	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error parsing ec private key: %s\n", err)
	}
	fmt.Println(bifrost.UUID(idNamespace, key.PublicKey))
}
