// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/RealImage/bifrost"
	"github.com/RealImage/bifrost/internal/sundry"
	"github.com/google/uuid"
)

const (
	usage = `bfid prints the UUID of a Bifrost public key, private key, or certificate.

Usage:
  bfid [-v] [-ns=UUID] FILE
  bfid [-v] [-ns=UUID] < FILE
`
)

var (
	namespace uuid.UUID
	verbose   bool
	filename  string = "-"
)

func init() {
	flag.Usage = func() {
		fmt.Fprint(os.Stderr, usage)
		flag.PrintDefaults()
	}
	var ns string
	flag.StringVar(&ns, "ns", uuid.Nil.String(),
		"Bifrost Identity Namespace")
	flag.BoolVar(&verbose, "v", false, "Verbose output")
	flag.Parse()
	// 0 or empty string means no namespace.
	if ns == "" || ns == "0" {
		namespace = uuid.Nil
	} else {
		var err error
		namespace, err = uuid.Parse(ns)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	if flag.NArg() > 1 {
		fmt.Fprintf(os.Stderr, "too many arguments\n\n")
		flag.Usage()
		os.Exit(1)
	}
	if flag.Arg(0) != "" {
		filename = flag.Arg(0)
	}
}

func main() {
	ctx := context.Background()
	// Read the input file or stdin.
	var data []byte
	var err error
	if filename == "-" {
		data, err = io.ReadAll(os.Stdin)
	} else {
		data, err = os.ReadFile(filename)
	}
	sundry.OnErrorExit(ctx, err, "error reading input")

	block, _ := pem.Decode(data)
	if block == nil {
		sundry.OnErrorExit(ctx, errors.New("no pem data found in input file"), "")
		return
	}

	// Parse the key or certificate.
	var pubkey *ecdsa.PublicKey
	switch block.Type {
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		sundry.OnErrorExit(ctx, err, "error parsing key")
		eckey, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			sundry.OnErrorExit(ctx, fmt.Errorf("unexpected key type: %T", key), "")
		}
		pubkey = &eckey.PublicKey
	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		sundry.OnErrorExit(ctx, err, "error parsing key")
		pubkey = &key.PublicKey
	case "PUBLIC KEY":
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		sundry.OnErrorExit(ctx, err, "error parsing key")
		eckey, ok := key.(*ecdsa.PublicKey)
		if !ok {
			sundry.OnErrorExit(ctx, fmt.Errorf("unexpected key type: %T", key), "")
		}
		pubkey = eckey
	case "CERTIFICATE":
		ns, _, key, err := bifrost.ParseCertificate(block.Bytes)
		sundry.OnErrorExit(ctx, err, "error parsing certificate")
		if namespace != uuid.Nil && namespace != ns {
			sundry.OnErrorExit(ctx, fmt.Errorf("ns doesn't match certificate namespace"), "")
		}
		pubkey = key
	default:
		sundry.OnErrorExit(ctx, fmt.Errorf("unexpected block type: %s", block.Type), "")
	}

	// Print the UUID.
	id := bifrost.UUID(namespace, pubkey)
	if verbose {
		fmt.Printf("namespace:\t%s\nuuid:\t\t%s\n", namespace, id)
	} else {
		fmt.Println(id)
	}
}
