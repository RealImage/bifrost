package main

import (
	"context"
	"encoding/pem"
	"fmt"

	"github.com/RealImage/bifrost"
	"github.com/RealImage/bifrost/cafiles"
	"github.com/google/uuid"
	"github.com/urfave/cli/v3"
)

var caUrl string

var requestCmd = &cli.Command{
	Name:    "request",
	Aliases: []string{"req"},
	Usage:   "Requests a certificate from a Certificate Authority server",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:        "ca-url",
			Usage:       "URL of the CA to request the certificate from",
			Sources:     cli.EnvVars("CA_URL"),
			Value:       fmt.Sprintf("http://%s:%d", defaultCaHost, defaultCaPort),
			Destination: &caUrl,
		},
		clientPrivKeyFlag,
		outputFlag,
	},
	Action: func(ctx context.Context, _ *cli.Command) error {
		if namespace == uuid.Nil {
			var err error
			if namespace, err = bifrost.GetNamespace(ctx, caUrl); err != nil {
				bifrost.Logger().ErrorContext(ctx, "error fetching namespace", "error", err)
				return cli.Exit("Namespace not provided and could not be fetched", 1)
			}
		}

		key, err := cafiles.GetPrivateKey(ctx, clientPrivKeyUri)
		if err != nil {
			bifrost.Logger().ErrorContext(ctx, "error reading private key", "error", err)
			return cli.Exit("Failed to read private key", 1)
		}

		cert, err := bifrost.RequestCertificate(ctx, caUrl, key)
		if err != nil {
			bifrost.Logger().ErrorContext(ctx, "error requesting certificate", "error", err)
			return cli.Exit("Failed to request certificate", 1)
		}

		block := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}

		out, cls, err := getOutputWriter()
		if err != nil {
			bifrost.Logger().ErrorContext(ctx, "error opening output file", "error", err)
			return cli.Exit("Failed to open output file", 1)
		}
		defer func() {
			if err := cls(); err != nil {
				bifrost.Logger().ErrorContext(ctx, "error closing output writer", "error", err)
			}
		}()

		if err := pem.Encode(out, block); err != nil {
			bifrost.Logger().ErrorContext(ctx, "error writing certificate", "error", err)
			return cli.Exit("Failed to write certificate", 1)
		}

		return nil
	},
}
