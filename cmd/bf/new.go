package main

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"github.com/RealImage/bifrost"
	"github.com/RealImage/bifrost/cafiles"
	"github.com/google/uuid"
	"github.com/urfave/cli/v2"
)

var newCmd = &cli.Command{
	Name:    "new",
	Aliases: []string{"n"},
	Usage:   "Create a new Bifrost namespace, identity, or certificate authority",
	Subcommands: []*cli.Command{
		{
			Name:    "namespace",
			Aliases: []string{"ns"},
			Usage:   "Create a new namespace",
			Flags: []cli.Flag{
				outputFlag,
			},
			Action: func(c *cli.Context) error {
				out, err := getOutputWriter()
				if err != nil {
					return err
				}

				fmt.Fprintln(out, uuid.New())
				return nil
			},
		},
		{
			Name:    "identity",
			Aliases: []string{"id"},
			Usage:   "Create a new identity",
			Flags: []cli.Flag{
				outputFlag,
			},
			Action: func(c *cli.Context) error {
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
			Name:    "ca-certificate",
			Aliases: []string{"ca-cert", "ca"},
			Flags: []cli.Flag{
				nsFlag,
				caPrivKeyFlag,
				outputFlag,
				&cli.DurationFlag{
					Name:  "validity",
					Usage: "certificate `VALIDITY`",
					Value: time.Hour * 24 * 365,
				},
			},
			Usage: "Create a new certificate authority signing certificate",
			Action: func(c *cli.Context) error {
				key, err := cafiles.GetPrivateKey(c.Context, caPrivKeyUri)
				if err != nil {
					return err
				}

				notBefore := time.Now()
				notAfter := notBefore.Add(c.Duration("validity"))

				// Create root certificate.
				template := x509.Certificate{
					SerialNumber: big.NewInt(2),
					Subject: pkix.Name{
						CommonName:   key.UUID(namespace).String(),
						Organization: []string{namespace.String()},
					},
					NotBefore:      notBefore,
					NotAfter:       notAfter,
					KeyUsage:       x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
					ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
					IsCA:           true,
					MaxPathLenZero: true,
				}

				certDer, err := x509.CreateCertificate(
					rand.Reader,
					&template,
					&template,
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
