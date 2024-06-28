package main

import (
	"context"
	"encoding/pem"
	"fmt"
	"log/slog"

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
		nsFlag,
		clientPrivKeyFlag,
		outputFlag,
	},
	Action: func(ctx context.Context, _ *cli.Command) error {
		if namespace == uuid.Nil {
			var err error
			if namespace, err = bifrost.GetNamespace(ctx, caUrl); err != nil {
				slog.ErrorContext(ctx, "error fetching namespace", "error", err)
				return cli.Exit("Namespace not provided and could not be fetched", 1)
			}
		}

		key, err := cafiles.GetPrivateKey(ctx, clientPrivKeyUri)
		if err != nil {
			slog.ErrorContext(ctx, "error reading private key", "error", err)
			return cli.Exit("Failed to read private key", 1)
		}

		cert, err := bifrost.RequestCertificate(ctx, caUrl, namespace, key)
		if err != nil {
			slog.ErrorContext(ctx, "error requesting certificate", "error", err)
			return cli.Exit("Failed to request certificate", 1)
		}

		block := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}

		out, cls, err := getOutputWriter()
		if err != nil {
			slog.ErrorContext(ctx, "error opening output file", "error", err)
			return cli.Exit("Failed to open output file", 1)
		}
		defer cls()

		if err := pem.Encode(out, block); err != nil {
			slog.ErrorContext(ctx, "error writing certificate", "error", err)
			return cli.Exit("Failed to write certificate", 1)
		}

		return nil
	},
}
