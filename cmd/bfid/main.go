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
	"time"

	"github.com/RealImage/bifrost"
	"github.com/google/uuid"
)

const (
	usageHeader = `bfid prints the UUID identifier of a bifrost identity file

Usage: bfid -ns=<uuid> <file.pem>
`
	usageTrailer = `	env BF_NS takes precedence over this flag.
0 or empty string means no namespace.
`
)

var namespace uuid.UUID

func init() {
	flag.Usage = func() {
		fmt.Fprint(os.Stderr, usageHeader)
		flag.PrintDefaults()
		fmt.Fprint(os.Stderr, usageTrailer)
	}
	var ns string
	flag.StringVar(&ns, "ns", bifrost.Namespace.String(),
		"Bifrost Identity Namespace")
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
	var filedata []byte
	var err error
	switch len(flag.Args()) {
	case 0:
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
	case 1:
		filedata, err = os.ReadFile(flag.Arg(0))
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

	fmt.Println(bifrost.UUID(namespace, pubkey))
}
