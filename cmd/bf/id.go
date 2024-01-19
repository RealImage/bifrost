package main

import (
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/RealImage/bifrost"
	"github.com/google/uuid"
	"github.com/urfave/cli/v2"
)

var (
	newNS bool
	newID bool
	newCA bool
	bfns  uuid.UUID
	id    = &cli.Command{
		Name:    "identity",
		Aliases: []string{"id"},
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:        "new-namespace",
				Aliases:     []string{"new-ns"},
				Destination: &newNS,
			},
			&cli.BoolFlag{
				Name:        "new-identitiy",
				Aliases:     []string{"new-id"},
				Destination: &newID,
			},
			&cli.BoolFlag{
				Name:        "new-certificate-authority",
				Aliases:     []string{"new-ca"},
				Destination: &newCA,
			},
			&cli.StringFlag{
				Name:    "namespace",
				Usage:   "Bifrost Namespace `UUID`",
				Aliases: []string{"n", "ns"},
				EnvVars: envvarNames("NS"),
				Action: func(ctx *cli.Context, s string) (err error) {
					if s != "" {
						bfns, err = uuid.Parse(s)
					}
					return
				},
			},
		},
		Action: func(cliCtx *cli.Context) error {
			if bfns == uuid.Nil && !newNS {
				return cli.Exit("Error: namespace not set", 1)
			}
			if newNS {
				bfns = uuid.New()
				slog.Info("new namespace generated")
			}
			slog.Info("using", "namespace", bfns)

			if newID && newCA {
				return cli.Exit(
					"Error: cannot set both --new-identity and --new-certificate-authority",
					1,
				)
			}

			if newID {
				pk, err := bifrost.NewPrivateKey()
				if err != nil {
					return cli.Exit(fmt.Sprintf("Error generating new private key: %s", err), 1)
				}
				fmt.Println(bifrost.UUID(bfns, *pk.PublicKey()))

			}

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
		return bifrost.UUID(bfns, *privkey.PublicKey()), nil
	case "EC PRIVATE KEY":
		privkey, err := bifrost.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return uuid.Nil, err
		}
		return bifrost.UUID(bfns, *privkey.PublicKey()), nil
	case "PUBLIC KEY":
		pubkey, err := bifrost.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return uuid.Nil, err
		}
		return bifrost.UUID(bfns, *pubkey), nil
	case "CERTIFICATE":
		cert, err := bifrost.ParseCertificate(block.Bytes)
		if err != nil {
			return uuid.Nil, err
		}
		return cert.PublicKey.UUID(bfns), nil
	default:
		return uuid.Nil, fmt.Errorf("unsupported PEM block type: %s", block.Type)
	}
}
