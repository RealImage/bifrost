package main

import (
	"io"
	"os"

	"github.com/google/uuid"
	"github.com/urfave/cli/v2"
)

// Flags
var (
	namespace uuid.UUID
	nsFlag    = &cli.StringFlag{
		Name:    "namespace",
		Usage:   "namespace `UUID`",
		Aliases: []string{"ns"},
		EnvVars: []string{"NS", "NAMESPACE"},
		Action: func(_ *cli.Context, ns string) (err error) {
			namespace, err = uuid.Parse(ns)
			return err
		},
	}

	caCertUri  string
	caCertFlag = &cli.StringFlag{
		Name:        "ca-certificate",
		Usage:       "read CA certificate from `FILE`",
		Aliases:     []string{"ca-cert"},
		EnvVars:     []string{"CA_CERT", "CA_CRT", "CRT"},
		TakesFile:   true,
		Value:       "cert.pem",
		Destination: &caCertUri,
	}

	caPrivKeyUri  string
	caPrivKeyFlag = &cli.StringFlag{
		Name:        "ca-private-key",
		Usage:       "read CA private key from `FILE`",
		Aliases:     []string{"ca-key"},
		EnvVars:     []string{"CA_PRIVKEY", "CA_KEY", "KEY"},
		TakesFile:   true,
		Value:       "key.pem",
		Destination: &caPrivKeyUri,
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

func getOutputWriter() (io.Writer, error) {
	if outputFile == "-" {
		return os.Stdout, nil
	}
	return os.Create(outputFile)
}
