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
			&cli.StringFlag{
				Name:     "namespace",
				Usage:    "Bifrost Namespace `UUID`",
				Aliases:  []string{"n", "ns"},
				EnvVars:  envvarNames("NS"),
				Required: true,
				Action: func(ctx *cli.Context, s string) (err error) {
					bfns, err = uuid.Parse(s)
					return
				},
			},
		},
		Action: func(cliCtx *cli.Context) error {
			id, err := parseUUIDFromFile(cliCtx.Args().First())
			if err != nil {
				return cli.Exit(fmt.Sprintf("Error parsing file: %s", err), 1)
			}

			fmt.Println(id)
			return nil
		},
	}
)

func parseUUIDFromFile(filename string) (uuid.UUID, error) {
	var data []byte
	var err error
	switch filename {
	case "", "-":
		data, err = io.ReadAll(os.Stdin)
	default:
		data, err = os.ReadFile(filename)
	}
	if err != nil {
		return uuid.Nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return uuid.Nil, errors.New("no PEM data found")
	}

	// Parse the key or certificate.
	switch block.Type {
	case "PRIVATE KEY":
		privkey, err := bifrost.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return uuid.Nil, err
		}
		return bifrost.UUID(bfns, privkey.PublicKey()), nil
	case "EC PRIVATE KEY":
		privkey, err := bifrost.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return uuid.Nil, err
		}
		return bifrost.UUID(bfns, privkey.PublicKey()), nil
	case "PUBLIC KEY":
		pubkey, err := bifrost.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return uuid.Nil, err
		}
		return bifrost.UUID(bfns, pubkey), nil
	case "CERTIFICATE":
		cert, err := bifrost.ParseCertificate(block.Bytes)
		if err != nil {
			return uuid.Nil, err
		}
		return cert.PublicKey.UUID(bfns), nil
	case "CERTIFICATE REQUEST":
		csr, err := bifrost.ParseCertificateRequest(block.Bytes)
		if err != nil {
			return uuid.Nil, err
		}
		return csr.PublicKey.UUID(bfns), nil
	default:
		return uuid.Nil, fmt.Errorf("unsupported PEM block type: %s", block.Type)
	}
}
