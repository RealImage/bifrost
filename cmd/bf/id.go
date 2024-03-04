package main

import (
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/RealImage/bifrost"
	"github.com/google/uuid"
	"github.com/urfave/cli/v2"
)

var (
	bfns  uuid.UUID
	idCmd = &cli.Command{
		Name:    "identity",
		Aliases: []string{"id"},
		Flags: []cli.Flag{
			nsFlag,
		},
		Action: func(cliCtx *cli.Context) error {
			ns, id, err := parseUUIDFromFile(bfns, cliCtx.Args().First())
			if err != nil {
				return cli.Exit(fmt.Sprintf("Error parsing file: %s", err), 1)
			}

			if ns == uuid.Nil {
				return cli.Exit("Error: Namespace is required", 1)
			}

			if bfns != ns {
				fmt.Printf("Namespace: %s\n", ns)
			}

			fmt.Println(id)
			return nil
		},
	}
)

func parseUUIDFromFile(ns uuid.UUID, filename string) (uuid.UUID, uuid.UUID, error) {
	var data []byte
	var err error
	switch filename {
	case "", "-":
		data, err = io.ReadAll(os.Stdin)
	default:
		data, err = os.ReadFile(filename)
	}
	if err != nil {
		return ns, uuid.Nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return ns, uuid.Nil, errors.New("no PEM data found")
	}

	// Parse the key or certificate.
	switch block.Type {
	case "PRIVATE KEY":
		privkey, err := bifrost.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return ns, uuid.Nil, err
		}
		return ns, bifrost.UUID(ns, privkey.PublicKey()), nil
	case "EC PRIVATE KEY":
		privkey, err := bifrost.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return ns, uuid.Nil, err
		}
		return ns, bifrost.UUID(ns, privkey.PublicKey()), nil
	case "PUBLIC KEY":
		pubkey, err := bifrost.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return ns, uuid.Nil, err
		}
		return ns, bifrost.UUID(ns, pubkey), nil
	case "CERTIFICATE":
		cert, err := bifrost.ParseCertificate(block.Bytes)
		if err != nil {
			return ns, uuid.Nil, err
		}
		ns = cert.Namespace
		return ns, cert.PublicKey.UUID(ns), nil
	case "CERTIFICATE REQUEST":
		csr, err := bifrost.ParseCertificateRequest(block.Bytes)
		if err != nil {
			return ns, uuid.Nil, err
		}
		ns = csr.Namespace
		return ns, csr.PublicKey.UUID(ns), nil
	default:
		return ns, uuid.Nil, fmt.Errorf("unsupported PEM block type: %s", block.Type)
	}
}
