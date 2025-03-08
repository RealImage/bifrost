package main

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/RealImage/bifrost"
	"github.com/RealImage/bifrost/cafiles"
	"github.com/RealImage/bifrost/internal/webapp"
	"github.com/RealImage/bifrost/tinyca"
	"github.com/urfave/cli/v3"
)

const (
	defaultCaHost         = "localhost"
	defaultCaPort         = 8008
	serverShutdownTimeout = 1 * time.Second
)

// caServeCmd flags
var (
	caHost         string
	caPort         int64
	enableCORS     bool
	exposeMetrics  bool
	gauntletPlugin string
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
			Name:        "cors",
			Usage:       "enable CORS from all origins",
			Sources:     cli.EnvVars("CORS"),
			Value:       false,
			Destination: &enableCORS,
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
			bifrost.Logger().ErrorContext(ctx, "error reading cert/key", "error", err)
			return cli.Exit("Error reading cert/key", 1)
		}
		bifrost.Logger().DebugContext(
			ctx, "loaded CA certificate and private key",
			"subject", cert.Subject,
			"notBefore", cert.NotBefore,
			"notAfter", cert.NotAfter,
		)

		gauntlet, err := tinyca.LoadGauntlet(gauntletPlugin)
		if err != nil {
			bifrost.Logger().ErrorContext(ctx, "error loading interceptor plugin", "error", err)
			return cli.Exit("Error loading interceptor plugin", 1)
		}

		ca, err := tinyca.New(cert, key, gauntlet)
		if err != nil {
			bifrost.Logger().ErrorContext(ctx, "error creating CA", "error", err)
			return cli.Exit("Error creating CA", 1)
		}
		defer ca.Close()

		mux := http.NewServeMux()
		ca.AddRoutes(mux, exposeMetrics)

		hdlr := webapp.RequestLogger(mux)

		if enableCORS {
			hdlr = corsMiddleware(hdlr)
		}

		addr := fmt.Sprintf("%s:%d", caHost, caPort)
		bifrost.Logger().
			InfoContext(ctx, "starting server", "address", addr, "namespace", cert.Namespace)

		server := http.Server{Addr: addr, Handler: hdlr}

		go func() {
			if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				bifrost.Logger().ErrorContext(ctx, "error starting server", "error", err)
				os.Exit(1)
			}
		}()

		ctx, cancel := signal.NotifyContext(ctx, os.Interrupt)
		defer cancel()

		<-ctx.Done()

		ctx, cancel = context.WithTimeout(context.Background(), serverShutdownTimeout)
		defer cancel()

		bifrost.Logger().DebugContext(ctx, "shutting down server")
		if err := server.Shutdown(ctx); err != nil {
			return err
		}
		bifrost.Logger().InfoContext(ctx, "server shut down")

		return nil
	},
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST")
		w.Header().Set("Access-Control-Allow-Headers",
			"Accept, Content-Type, Content-Length, Accept-Encoding")

		if r.Method == http.MethodOptions {
			return
		}

		next.ServeHTTP(w, r)
	})
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
			bifrost.Logger().ErrorContext(ctx, "error reading cert/key", "error", err)
			return cli.Exit("Error reading cert/key", 1)
		}

		ca, err := tinyca.New(caCert, caKey, nil)
		if err != nil {
			bifrost.Logger().ErrorContext(ctx, "error creating CA", "error", err)
			return cli.Exit("Error creating CA", 1)
		}
		defer ca.Close()

		clientKey, err := cafiles.GetPrivateKey(ctx, clientPrivKeyUri)
		if err != nil {
			bifrost.Logger().ErrorContext(ctx, "error reading client key", "error", err)
			return cli.Exit("Error reading client key", 1)
		}

		csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
			Subject: pkix.Name{
				Organization: []string{caCert.Namespace.String()},
				CommonName:   clientKey.UUID(caCert.Namespace).String(),
			},
		}, clientKey)
		if err != nil {
			bifrost.Logger().ErrorContext(ctx, "error creating certificate request", "error", err)
			return cli.Exit("Error creating certificate request", 1)
		}

		notBefore, notAfter, err := tinyca.ParseValidity(
			notBeforeTime,
			notAfterTime,
			tinyca.MaximumIssueValidity,
		)
		if err != nil {
			bifrost.Logger().ErrorContext(ctx, "error parsing validity", "error", err)
			return cli.Exit("Error parsing validity", 1)
		}

		cert, err := ca.IssueCertificate(csr, notBefore, notAfter)
		if err != nil {
			bifrost.Logger().ErrorContext(ctx, "error issuing certificate", "error", err)
			return cli.Exit("Error issuing certificate", 1)
		}

		out, cls, err := getOutputWriter()
		if err != nil {
			bifrost.Logger().ErrorContext(ctx, "error getting output writer", "error", err)
			return cli.Exit("Error getting output writer", 1)
		}
		defer func() {
			if err := cls(); err != nil {
				bifrost.Logger().ErrorContext(ctx, "error closing output writer", "error", err)
			}
		}()

		block := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert,
		}

		return pem.Encode(out, block)
	},
}
