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
	Usage:   "Create a new Bifrost namespace, identity, or certificate authority",
	Commands: []*cli.Command{
		{
			Name:    "namespace",
			Aliases: []string{"ns"},
			Usage:   "Create a new namespace",
			Flags: []cli.Flag{
				outputFlag,
			},
			Action: func(_ context.Context, _ *cli.Command) error {
				out, err := getOutputWriter()
				if err != nil {
					return err
				}

				fmt.Fprintln(out, uuid.New())
				return nil
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
				asn1Der, err := bifrost.MarshalECPrivateKey(key)
				if err != nil {
					return err
				}
				block := &pem.Block{
					Type:  "EC PRIVATE KEY",
					Bytes: asn1Der,
				}

				out, err := getOutputWriter()
				if err != nil {
					return err
				}
				fmt.Fprint(out, string(pem.EncodeToMemory(block)))
				return nil
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

				out, err := getOutputWriter()
				if err != nil {
					return err
				}

				block := &pem.Block{
					Type:  "CERTIFICATE REQUEST",
					Bytes: csr,
				}
				fmt.Fprint(out, string(pem.EncodeToMemory(block)))

				return nil
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

				template := tinyca.CACertTemplate(notBefore, notAfter, namespace, id)

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

				out, err := getOutputWriter()
				if err != nil {
					return err
				}

				block := &pem.Block{
					Type:  "CERTIFICATE",
					Bytes: certDer,
				}
				fmt.Fprint(out, string(pem.EncodeToMemory(block)))

				return nil
			},
		},
	},
}
