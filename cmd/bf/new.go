package main

import (
	"encoding/pem"
	"fmt"

	"github.com/RealImage/bifrost"
	"github.com/google/uuid"
	"github.com/urfave/cli/v2"
)

var newCmd = &cli.Command{
	Name:    "new",
	Aliases: []string{"n"},
	Usage:   "Create a new Bifrost namespace, identity, or certificate authority",
	Subcommands: []*cli.Command{
		{
			Name:    "namespace",
			Aliases: []string{"ns"},
			Usage:   "Create a new namespace",
			Action: func(c *cli.Context) error {
				fmt.Println(uuid.New().String())
				return nil
			},
		},
		{
			Name:    "identity",
			Aliases: []string{"id"},
			Usage:   "Create a new identity",
			Action: func(c *cli.Context) error {
				key, err := bifrost.NewPrivateKey()
				if err != nil {
					return err
				}
				asn1Der, err := bifrost.MarshalECPrivateKey(key)
				if err != nil {
					return err
				}
				block := &pem.Block{
					Type:  "EC PRIVATE KEY",
					Bytes: asn1Der,
				}
				fmt.Print(string(pem.EncodeToMemory(block)))
				return nil
			},
		},
		{
			Name:    "ca-certificate",
			Aliases: []string{"ca-cert", "ca"},
			Flags: []cli.Flag{
				caCertFlag,
				caKeyFlag,
			},
			Usage: "Create a new certificate authority signing certificate",
			Action: func(c *cli.Context) error {
				return nil
			},
		},
		{
			Name:    "tls-certificate",
			Aliases: []string{"tls-cert", "tls"},
			Flags: []cli.Flag{
				caCertFlag,
				caKeyFlag,
			},
			Usage: "Create a new TLS server certificate",
			Action: func(c *cli.Context) error {
				return nil
			},
		},
	},
}
