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
	"os"
	"os/signal"
	"time"

	"github.com/RealImage/bifrost/cafiles"
	"github.com/RealImage/bifrost/internal/webapp"
	"github.com/RealImage/bifrost/tinyca"
	"github.com/urfave/cli/v3"
)

const (
	defaultCaHost = "localhost"
	defaultCaPort = 8008
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
	Usage:   "Starts the Certificate Authority server",
	Flags: []cli.Flag{
		caCertFlag,
		caPrivKeyFlag,
		&cli.StringFlag{
			Name:        "host",
			Usage:       "listen on `HOST`",
			Aliases:     []string{"H"},
			Sources:     cli.EnvVars("HOST"),
			Value:       defaultCaHost,
			Destination: &caHost,
		},
		&cli.IntFlag{
			Name:        "port",
			Usage:       "listen on `PORT`",
			Aliases:     []string{"p"},
			Sources:     cli.EnvVars("PORT"),
			Value:       defaultCaPort,
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
			slog.ErrorContext(ctx, "error reading cert/key", "error", err)
			return cli.Exit("Error reading cert/key", 1)
		}
		slog.DebugContext(
			ctx, "loaded CA certificate and private key",
			"subject", cert.Subject,
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
			slog.ErrorContext(ctx, "error creating CA", "error", err)
			return cli.Exit("Error creating CA", 1)
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

		hdlr := webapp.RequestLogger(mux)

		addr := fmt.Sprintf("%s:%d", caHost, caPort)
		slog.InfoContext(ctx, "starting server", "address", addr, "namespace", nss)

		server := http.Server{Addr: addr, Handler: hdlr}

		ctx, cancel := signal.NotifyContext(ctx, os.Interrupt)
		defer cancel()

		go func() {
			<-ctx.Done()

			const serverShutdownTimeout = 1 * time.Second
			ctx, cancel := context.WithTimeout(context.Background(), serverShutdownTimeout)
			defer cancel()
			slog.DebugContext(ctx, "shutting down server")
			if err := server.Shutdown(ctx); err != nil {
				slog.Error("error shutting down server", "error", err)
			}
			slog.InfoContext(ctx, "server shut down")
		}()

		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.ErrorContext(ctx, "error starting server", "error", err)
			return cli.Exit("Error starting server", 1)
		}

		return nil
	},
}

var caIssueCmd = &cli.Command{
	Name:  "issue",
	Usage: "Issues a certificate from the Certificate Authority key",
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
			slog.ErrorContext(ctx, "error reading cert/key", "error", err)
			return cli.Exit("Error reading cert/key", 1)
		}

		ca, err := tinyca.New(caCert, caKey, nil)
		if err != nil {
			slog.ErrorContext(ctx, "error creating CA", "error", err)
			return cli.Exit("Error creating CA", 1)
		}
		defer ca.Close()

		clientKey, err := cafiles.GetPrivateKey(ctx, clientPrivKeyUri)
		if err != nil {
			slog.ErrorContext(ctx, "error reading client key", "error", err)
			return cli.Exit("Error reading client key", 1)
		}

		csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
			Subject: pkix.Name{
				Organization: []string{caCert.Namespace.String()},
				CommonName:   clientKey.UUID(caCert.Namespace).String(),
			},
		}, clientKey)
		if err != nil {
			slog.ErrorContext(ctx, "error creating certificate request", "error", err)
			return cli.Exit("Error creating certificate request", 1)
		}

		notBefore, notAfter, err := tinyca.ParseValidity(notBeforeTime, notAfterTime)
		if err != nil {
			slog.ErrorContext(ctx, "error parsing validity", "error", err)
			return cli.Exit("Error parsing validity", 1)
		}

		cert, err := ca.IssueCertificate(csr, notBefore, notAfter)
		if err != nil {
			slog.ErrorContext(ctx, "error issuing certificate", "error", err)
			return cli.Exit("Error issuing certificate", 1)
		}

		out, err := getOutputWriter()
		if err != nil {
			slog.ErrorContext(ctx, "error getting output writer", "error", err)
			return cli.Exit("Error getting output writer", 1)
		}

		block := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert,
		}

		return pem.Encode(out, block)
	},
}
