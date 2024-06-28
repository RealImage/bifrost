package main

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"

	"github.com/RealImage/bifrost"
	"github.com/RealImage/bifrost/cafiles"
	"github.com/RealImage/bifrost/tinyca"
	"github.com/google/uuid"
	"github.com/urfave/cli/v3"
)

var newCmd = &cli.Command{
	Name:    "new",
	Aliases: []string{"n"},
	Usage:   "Creates a new namespace, private key, or Certificate Authority certificate",
	Commands: []*cli.Command{
		{
			Name:    "namespace",
			Aliases: []string{"ns"},
			Usage:   "Create a new namespace",
			Flags: []cli.Flag{
				outputFlag,
			},
			Action: func(_ context.Context, _ *cli.Command) error {
				out, cls, err := getOutputWriter()
				if err != nil {
					return err
				}
				defer cls()

				_, err = out.Write([]byte(uuid.New().String() + "\n"))
				return err
			},
		},
		{
			Name:    "private-key",
			Aliases: []string{"key", "pk", "pkey"},
			Usage:   "Create a new identity",
			Flags: []cli.Flag{
				outputFlag,
			},
			Action: func(_ context.Context, _ *cli.Command) error {
				key, err := bifrost.NewPrivateKey()
				if err != nil {
					return err
				}

				keyText, err := key.MarshalText()
				if err != nil {
					return err
				}

				out, cls, err := getOutputWriter()
				if err != nil {
					return err
				}
				defer cls()

				_, err = out.Write(keyText)
				return err
			},
		},
		{
			Name:    "certificate-request",
			Aliases: []string{"csr", "req"},
			Flags: []cli.Flag{
				nsFlag,
				clientPrivKeyFlag,
				outputFlag,
			},
			Usage: "Create a new certificate request",
			Action: func(ctx context.Context, _ *cli.Command) error {
				if namespace == uuid.Nil {
					return fmt.Errorf("namespace is required")
				}

				key, err := cafiles.GetPrivateKey(ctx, clientPrivKeyUri)
				if err != nil {
					return err
				}

				csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
					Subject: pkix.Name{
						Organization: []string{namespace.String()},
						CommonName:   key.UUID(namespace).String(),
					},
				}, key)
				if err != nil {
					return err
				}

				out, cls, err := getOutputWriter()
				if err != nil {
					return err
				}
				defer cls()

				block := &pem.Block{
					Type:  "CERTIFICATE REQUEST",
					Bytes: csr,
				}
				_, err = out.Write(pem.EncodeToMemory(block))
				return err
			},
		},
		{
			Name:    "ca-certificate",
			Aliases: []string{"ca-cert", "ca"},
			Flags: []cli.Flag{
				nsFlag,
				caPrivKeyFlag,
				outputFlag,
				notBeforeFlag,
				notAfterFlag,
			},
			Usage: "Create a new certificate authority signing certificate",
			Action: func(ctx context.Context, _ *cli.Command) error {
				if namespace == uuid.Nil {
					return fmt.Errorf("namespace is required")
				}

				key, err := cafiles.GetPrivateKey(ctx, caPrivKeyUri)
				if err != nil {
					return err
				}

				id := key.UUID(namespace)
				notBefore, notAfter, err := tinyca.ParseValidity(notBeforeTime, notAfterTime)
				if err != nil {
					return err
				}

				template, err := tinyca.CACertTemplate(namespace, id)
				if err != nil {
					return err
				}
				template.NotBefore = notBefore
				template.NotAfter = notAfter

				certDer, err := x509.CreateCertificate(
					rand.Reader,
					template,
					template,
					key.PublicKey().PublicKey,
					key,
				)
				if err != nil {
					return err
				}

				out, cls, err := getOutputWriter()
				if err != nil {
					return err
				}
				defer cls()

				block := &pem.Block{
					Type:  "CERTIFICATE",
					Bytes: certDer,
				}

				_, err = out.Write(pem.EncodeToMemory(block))
				return err
			},
		},
	},
}
