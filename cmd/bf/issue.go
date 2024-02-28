package main

import (
	"fmt"
	"time"

	"github.com/RealImage/bifrost/cafiles"
	"github.com/RealImage/bifrost/tinyca"
	"github.com/urfave/cli/v2"
)

var (
	notBefore cli.Timestamp
	notAfter  cli.Timestamp

	issueCmd = &cli.Command{
		Name: "issue",
		Flags: []cli.Flag{
			caCertFlag,
			caPrivKeyFlag,
			&cli.TimestampFlag{
				Name:        "not-before",
				Usage:       "issue certificates valid from `TIMESTAMP`",
				Aliases:     []string{"before"},
				EnvVars:     []string{"NOT_BEFORE"},
				Value:       cli.NewTimestamp(time.Now()),
				Destination: &notBefore,
			},
			&cli.TimestampFlag{
				Name:        "not-after",
				Usage:       "issue certificates valid until `TIMESTAMP`",
				Aliases:     []string{"after"},
				EnvVars:     []string{"NOT_AFTER"},
				Value:       cli.NewTimestamp(time.Now().AddDate(0, 0, 1)),
				Destination: &notAfter,
			},
		},

		Action: func(cliCtx *cli.Context) error {
			ctx := cliCtx.Context
			cert, key, err := cafiles.GetCertKey(ctx, caCertUri, caPrivKeyUri)
			if err != nil {
				return cli.Exit(fmt.Sprintf("Error reading cert/key: %s", err), 1)
			}

			_, err = tinyca.New(cert, key)
			if err != nil {
				return cli.Exit(fmt.Sprintf("Error creating CA: %s", err), 1)
			}

			return nil
		},
	}
)
