package main

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"

	"github.com/RealImage/bifrost/cafiles"
	"github.com/RealImage/bifrost/tinyca"
	"github.com/urfave/cli/v2"
)

var issueCmd = &cli.Command{
	Name: "issue",
	Flags: []cli.Flag{
		caCertFlag,
		caPrivKeyFlag,
		clientPrivKeyFlag,
		notBeforeFlag,
		notAfterFlag,
		outputFlag,
	},

	Action: func(cliCtx *cli.Context) error {
		ctx := cliCtx.Context
		caCert, caKey, err := cafiles.GetCertKey(ctx, caCertUri, caPrivKeyUri)
		if err != nil {
			return cli.Exit(fmt.Sprintf("Error reading cert/key: %s", err), 1)
		}

		ca, err := tinyca.New(caCert, caKey)
		if err != nil {
			return cli.Exit(fmt.Sprintf("Error creating CA: %s", err), 1)
		}

		clientKey, err := cafiles.GetPrivateKey(ctx, clientPrivKeyUri)
		if err != nil {
			return cli.Exit(fmt.Sprintf("Error reading client key: %s", err), 1)
		}

		csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
			Subject: pkix.Name{
				Organization: []string{caCert.Namespace.String()},
				CommonName:   clientKey.UUID(caCert.Namespace).String(),
			},
		}, clientKey)
		if err != nil {
			return cli.Exit(fmt.Sprintf("Error creating certificate request: %s", err), 1)
		}

		notBefore, notAfter, err := tinyca.ParseValidity(notBeforeTime, notAfterTime)
		if err != nil {
			return cli.Exit(fmt.Sprintf("Error parsing validity: %s", err), 1)
		}

		template := tinyca.TLSClientCertTemplate(notBefore, notAfter)

		cert, err := ca.IssueCertificate(csr, template)
		if err != nil {
			return cli.Exit(fmt.Sprintf("Error issuing certificate: %s", err), 1)
		}

		out, err := getOutputWriter()
		if err != nil {
			return cli.Exit(fmt.Sprintf("Error getting output writer: %s", err), 1)
		}

		block := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert,
		}

		fmt.Fprint(out, string(pem.EncodeToMemory(block)))

		return nil
	},
}
