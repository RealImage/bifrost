package main

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/RealImage/bifrost/cafiles"
	"github.com/RealImage/bifrost/internal/webapp"
	"github.com/RealImage/bifrost/tinyca"
	"github.com/urfave/cli/v3"
)

// caServeCmd flags
var (
	caHost        string
	caPort        int64
	webEnabled    bool
	webStaticPath string
	exposeMetrics bool
)

var caServeCmd = &cli.Command{
	Name:    "serve",
	Aliases: []string{"ca"},
	Flags: []cli.Flag{
		caCertFlag,
		caPrivKeyFlag,
		&cli.StringFlag{
			Name:        "host",
			Usage:       "listen on `HOST`",
			Aliases:     []string{"H"},
			Sources:     cli.EnvVars("HOST"),
			Value:       "localhost",
			Destination: &caHost,
			Action: func(_ context.Context, _ *cli.Command, h string) error {
				if h == "" {
					return errors.New("host cannot be empty")
				}
				return nil
			},
		},
		&cli.IntFlag{
			Name:        "port",
			Usage:       "listen on `PORT`",
			Aliases:     []string{"p"},
			Sources:     cli.EnvVars("PORT"),
			Value:       8008,
			Destination: &caPort,
			Action: func(_ context.Context, _ *cli.Command, p int64) error {
				if p < 1 || p > 65535 {
					return errors.New("port must be between 1 and 65535")
				}
				return nil
			},
		},
		&cli.BoolFlag{
			Name:        "web",
			Usage:       "enable web interface",
			Aliases:     []string{"w"},
			Sources:     cli.EnvVars("WEB"),
			Destination: &webEnabled,
		},
		&cli.StringFlag{
			Name:        "web-static-path",
			Usage:       "read web static files from `PATH`",
			Sources:     cli.EnvVars("WEB_STATIC_PATH"),
			Value:       "embed",
			Destination: &webStaticPath,
		},
		&cli.BoolFlag{
			Name:        "metrics",
			Usage:       "expose Prometheus metrics",
			Sources:     cli.EnvVars("METRICS"),
			Value:       false,
			Destination: &exposeMetrics,
		},
	},
	Action: func(ctx context.Context, _ *cli.Command) error {
		cert, key, err := cafiles.GetCertKey(ctx, caCertUri, caPrivKeyUri)
		if err != nil {
			return cli.Exit(fmt.Sprintf("Error reading cert/key: %s", err), 1)
		}
		slog.DebugContext(
			ctx, "loaded CA certificate and private key",
			"notBefore", cert.NotBefore,
			"notAfter", cert.NotAfter,
		)

		mux := http.NewServeMux()

		if exposeMetrics {
			slog.InfoContext(ctx, "metrics enabled")
			mux.HandleFunc("GET /metrics", webapp.MetricsHandler)
		}

		ca, err := tinyca.New(cert, key, nil)
		if err != nil {
			return cli.Exit(fmt.Sprintf("Error creating CA: %s", err), 1)
		}
		defer ca.Close()

		mux.Handle("POST /issue", ca)

		nss := cert.Namespace.String()
		mux.HandleFunc("GET /namespace", func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, nss)
		})

		if webEnabled {
			slog.InfoContext(ctx, "web interface enabled", "staticPath", webStaticPath)
			webapp.AddRoutes(mux, webStaticPath, cert.Namespace)
		}

		hdlr := webapp.RequestLogHandler(mux)

		addr := fmt.Sprintf("%s:%d", caHost, caPort)
		slog.InfoContext(ctx, "starting server", "address", addr, "namespace", nss)

		server := http.Server{Addr: addr, Handler: hdlr}
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return cli.Exit(fmt.Sprintf("Error starting server: %s", err), 1)
		}

		return nil
	},
}

var caIssueCmd = &cli.Command{
	Name: "issue",
	Flags: []cli.Flag{
		caCertFlag,
		caPrivKeyFlag,
		clientPrivKeyFlag,
		notBeforeFlag,
		notAfterFlag,
		outputFlag,
	},

	Action: func(ctx context.Context, _ *cli.Command) error {
		caCert, caKey, err := cafiles.GetCertKey(ctx, caCertUri, caPrivKeyUri)
		if err != nil {
			return cli.Exit(fmt.Sprintf("Error reading cert/key: %s", err), 1)
		}

		ca, err := tinyca.New(caCert, caKey, nil)
		if err != nil {
			return cli.Exit(fmt.Sprintf("Error creating CA: %s", err), 1)
		}
		defer ca.Close()

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

		cert, err := ca.IssueCertificate(csr, notBefore, notAfter)
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
