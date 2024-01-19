package main

import (
	"time"

	"github.com/urfave/cli/v2"
)

func envvarNames(s string) []string {
	return []string{s, "BF_" + s}
}

// Flags
var (
	certUri  string
	certFlag = &cli.StringFlag{
		Name:        "certificate",
		Usage:       "read CA certificate from `FILE`",
		Aliases:     []string{"c", "crt", "cert"},
		EnvVars:     envvarNames("CERT"),
		Value:       "cert.pem",
		Destination: &certUri,
	}

	privKeyUri string
	keyFlag    = &cli.StringFlag{
		Name:        "private-key",
		Usage:       "read CA private key from `FILE`",
		Aliases:     []string{"k", "key"},
		EnvVars:     envvarNames("KEY"),
		Value:       "key.pem",
		Destination: &privKeyUri,
	}

	issueValidity  time.Duration
	issueValidFlag = &cli.DurationFlag{
		Name:        "issue-validity",
		Usage:       "issue certificates valid for `DURATION`",
		Aliases:     []string{"v", "valid"},
		EnvVars:     envvarNames("ISSUE_VALIDITY"),
		Value:       time.Hour,
		Destination: &issueValidity,
	}
)
