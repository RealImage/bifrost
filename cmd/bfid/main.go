package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/RealImage/bifrost"
	"github.com/google/uuid"
)

const (
	usageHeader = `bfid prints the UUID identifier of a bifrost identity file

Usage: bfid -namespace=<uuid> <file.pem>
input file must be a PEM encoded ECDSA public key or private key
`
	usageTrailer = `	env BFID_NAMESPACE takes precedence over this flag
`
)

var namespace string

func init() {
	flag.Usage = func() {
		fmt.Fprint(os.Stderr, usageHeader)
		flag.PrintDefaults()
		fmt.Fprint(os.Stderr, usageTrailer)
	}
	flag.StringVar(&namespace, "namespace", bifrost.NamespaceBifrost.String(),
		"Bifrost Identity Namespace")
	flag.Parse()
}

func main() {
	// BFID_NAMESPACE env var overrides the flag
	if n := os.Getenv("BFID_NAMESPACE"); n != "" {
		namespace = n
	}
	idNamespace, err := uuid.Parse(namespace)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error parsing id namespace `%s`: %s", namespace, err)
		os.Exit(1)
	}

	var filedata []byte
	switch len(os.Args) {
	case 1:
		done := make(chan struct{})
		go func() {
			filedata, err = io.ReadAll(os.Stdin)
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(time.Second * 2):
			err = fmt.Errorf("timed out waiting for stdin")
		}
	case 2:
		filedata, err = os.ReadFile(os.Args[1])
	default:
		err = fmt.Errorf("too many arguments")
	}
	if err != nil {
		fmt.Fprintf(os.Stderr,
			"error: %s, expects an identity file\n\ntry: bfid <file> or echo file | bfid\n", err)
		os.Exit(1)
	}

	block, _ := pem.Decode(filedata)
	if block == nil {
		fmt.Fprint(os.Stderr, "no pem data found in input file\n")
		os.Exit(1)
	}

	var pubkey ecdsa.PublicKey
	switch block.Type {
	case "PRIVATE KEY":
		var key any
		if key, err = x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
			if eckey, ok := key.(*ecdsa.PrivateKey); ok {
				pubkey = eckey.PublicKey
			} else {
				err = fmt.Errorf("unsupported private key algorithm")
			}
		}
	case "EC PRIVATE KEY":
		var key *ecdsa.PrivateKey
		if key, err = x509.ParseECPrivateKey(block.Bytes); err == nil {
			pubkey = key.PublicKey
		}
	case "PUBLIC KEY":
		var key any
		if key, err = x509.ParsePKIXPublicKey(block.Bytes); err == nil {
			if eckey, ok := key.(*ecdsa.PublicKey); ok {
				pubkey = *eckey
			} else {
				err = fmt.Errorf("unsupported public key algorithm")
			}
		}
	default:
		err = fmt.Errorf("expected ecdsa private key or public key")
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error parsing key: %s\n", err)
		os.Exit(1)
	}

	fmt.Println(bifrost.UUID(idNamespace, pubkey))
}
