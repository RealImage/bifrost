package main

import (
	"context"
	"io"
	"os"

	"github.com/google/uuid"
	"github.com/urfave/cli/v3"
)

// Flags
var (
	namespace uuid.UUID
	nsFlag    = &cli.StringFlag{
		Name:    "namespace",
		Usage:   "namespace `UUID`",
		Aliases: []string{"ns"},
		Sources: cli.EnvVars("NS", "NAMESPACE"),
		Action: func(_ context.Context, _ *cli.Command, ns string) (err error) {
			namespace, err = uuid.Parse(ns)
			return err
		},
	}

	caCertUri  string
	caCertFlag = &cli.StringFlag{
		Name:        "ca-certificate",
		Usage:       "read CA certificate from `URI`",
		Aliases:     []string{"ca-cert"},
		Sources:     cli.EnvVars("CA_CERT", "CA_CRT", "CRT"),
		TakesFile:   true,
		Value:       "cert.pem",
		Destination: &caCertUri,
	}

	caPrivKeyUri  string
	caPrivKeyFlag = &cli.StringFlag{
		Name:        "ca-private-key",
		Usage:       "read CA private key from `URI`",
		Aliases:     []string{"ca-key"},
		Sources:     cli.EnvVars("CA_PRIVKEY", "CA_KEY", "KEY"),
		TakesFile:   true,
		Value:       "key.pem",
		Destination: &caPrivKeyUri,
	}

	clientPrivKeyUri  string
	clientPrivKeyFlag = &cli.StringFlag{
		Name:        "client-private-key",
		Usage:       "read CA private key from `FILE`",
		Aliases:     []string{"client-key"},
		Sources:     cli.EnvVars("CLIENT_PRIVKEY", "CLIENT_KEY"),
		TakesFile:   true,
		Value:       "clientkey.pem",
		Destination: &clientPrivKeyUri,
	}

	notBeforeTime string
	notBeforeFlag = &cli.StringFlag{
		Name:        "not-before",
		Usage:       "certificate valid from `TIMESPEC` (default: \"now\")",
		Aliases:     []string{"before"},
		Sources:     cli.EnvVars("NOT_BEFORE"),
		Destination: &notBeforeTime,
	}
	notAfterTime string
	notAfterFlag = &cli.StringFlag{
		Name:        "not-after",
		Usage:       "certificate valid until `TIMESPEC` (default: \"+1h\")",
		Aliases:     []string{"after"},
		Sources:     cli.EnvVars("NOT_AFTER"),
		Destination: &notAfterTime,
	}

	outputFile string
	outputFlag = &cli.StringFlag{
		Name:        "output",
		Usage:       "write output to `FILE`",
		Aliases:     []string{"o"},
		TakesFile:   true,
		Value:       "-",
		Destination: &outputFile,
	}
)

func getOutputWriter() (io.WriteCloser, func() error, error) {
	if outputFile == "" || outputFile == "-" {
		return os.Stdout, func() error { return nil }, nil
	}

	f, err := os.Create(outputFile)
	return f, f.Close, err
}
