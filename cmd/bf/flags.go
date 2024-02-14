package main

import (
	"github.com/urfave/cli/v2"
)

func envvarNames(s string) []string {
	return []string{s, "BF_" + s}
}

// Flags
var (
	caCertUri  string
	caCertFlag = &cli.StringFlag{
		Name:        "ca-certificate",
		Usage:       "read CA certificate from `FILE`",
		Aliases:     []string{"ca-cert"},
		EnvVars:     envvarNames("CA_CERTIFICATE"),
		Value:       "cert.pem",
		Destination: &caCertUri,
	}

	caPrivKeyUri string
	caKeyFlag    = &cli.StringFlag{
		Name:        "ca-private-key",
		Usage:       "read CA private key from `FILE`",
		Aliases:     []string{"ca-key"},
		EnvVars:     envvarNames("CA_PRIVATE_KEY"),
		Value:       "key.pem",
		Destination: &caPrivKeyUri,
	}
)
