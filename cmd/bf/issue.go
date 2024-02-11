package main

import (
	"fmt"

	"github.com/RealImage/bifrost/cafiles"
	"github.com/RealImage/bifrost/tinyca"
	"github.com/urfave/cli/v2"
)

var issueCmd = &cli.Command{
	Name: "issue",
	Flags: []cli.Flag{
		certFlag,
		keyFlag,
		issueValidFlag,
	},

	Action: func(cliCtx *cli.Context) error {
		ctx := cliCtx.Context
		cert, key, err := cafiles.GetCertKey(ctx, certUri, privKeyUri)
		if err != nil {
			return cli.Exit(fmt.Sprintf("Error reading cert/key: %s", err), 1)
		}

		_, err = tinyca.New(cert, key, issueValidity)
		if err != nil {
			return cli.Exit(fmt.Sprintf("Error creating CA: %s", err), 1)
		}

		return nil
	},
}
