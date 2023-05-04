// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/RealImage/bifrost"
	"github.com/google/uuid"
)

const (
	usageHeader = `bfid prints the UUID of a Bifrost public key, private key, or certificate.

Usage:
  bfid [-v] [-ns=UUID] FILE
  bfid [-v] [-ns=UUID] < FILE
`
	usageTrailer = `
The environment variable BF_NS takes precedence over the -ns flag.
`
)

var (
	namespace uuid.UUID
	verbose   bool
)

func init() {
	flag.Usage = func() {
		fmt.Fprint(os.Stderr, usageHeader)
		flag.PrintDefaults()
		fmt.Fprint(os.Stderr, usageTrailer)
	}
	var ns string
	flag.StringVar(&ns, "ns", bifrost.Namespace.String(),
		"Bifrost Identity Namespace")
	flag.BoolVar(&verbose, "v", false, "Verbose output")
	flag.Parse()
	// BF_NS env var overrides the flag.
	if n, ok := os.LookupEnv("BF_NS"); ok {
		ns = n
	}
	// 0 or empty string means no namespace.
	if ns == "" || ns == "0" {
		namespace = uuid.Nil
	} else {
		namespace = uuid.MustParse(ns)
	}
}

func main() {
	args := flag.Args()
	if len(args) > 1 {
		fmt.Fprint(os.Stderr, "too many arguments")
		os.Exit(1)
	}
	// Read the input file or stdin.
	var data []byte
	var err error
	if len(args) == 1 {
		data, err = os.ReadFile(args[0])
	} else {
		data, err = io.ReadAll(os.Stdin)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading input: %s\n", err)
		os.Exit(1)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		fmt.Fprint(os.Stderr, "no pem data found in input file\n")
		os.Exit(1)
	}
	// Parse the key or certificate.
	var pubkey *ecdsa.PublicKey
	var unknownBlock bool
	switch block.Type {
	case "PRIVATE KEY":
		var key any
		if key, err = x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
			if eckey, ok := key.(*ecdsa.PrivateKey); ok {
				pubkey = &eckey.PublicKey
			}
		}
	case "EC PRIVATE KEY":
		var key *ecdsa.PrivateKey
		if key, err = x509.ParseECPrivateKey(block.Bytes); err == nil {
			pubkey = &key.PublicKey
		}
	case "PUBLIC KEY":
		var key any
		if key, err = x509.ParsePKIXPublicKey(block.Bytes); err == nil {
			if eckey, ok := key.(*ecdsa.PublicKey); ok {
				pubkey = eckey
			}
		}
	case "CERTIFICATE":
		var cert *x509.Certificate
		if _, cert, err = bifrost.ParseCertificate(block.Bytes); err == nil {
			if eckey, ok := cert.PublicKey.(*ecdsa.PublicKey); ok {
				pubkey = eckey
			}
		}
	default:
		err = fmt.Errorf("unexpected block type: %s", block.Type)
		unknownBlock = true
	}
	if unknownBlock && pubkey == nil {
		err = bifrost.ErrUnsupportedAlgorithm
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error parsing key: %s\n", err)
		os.Exit(1)
	}
	// Print the UUID.
	id := bifrost.UUID(namespace, pubkey)
	if verbose {
		fmt.Printf("namespace:\t%s\nuuid:\t\t%s\n", namespace, id)
	} else {
		fmt.Println(id)
	}
}
