package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"time"

	"github.com/RealImage/bifrost/asgard"
	"github.com/RealImage/bifrost/cafiles"
	"github.com/RealImage/bifrost/internal/sundry"
	"github.com/urfave/cli/v2"
)

var (
	backendUrl    *url.URL
	proxyHost     string
	proxyPort     int
	sslLogfile    string
	identityProxy = &cli.Command{
		Name:    "identity-proxy",
		Aliases: []string{"proxy", "id-proxy"},
		Flags: []cli.Flag{
			certFlag,
			keyFlag,
			&cli.StringFlag{
				Name:    "backend-url",
				Aliases: []string{"b"},
				Value:   "http://localhost:8080",
				Action: func(_ *cli.Context, s string) (err error) {
					backendUrl, err = url.Parse(s)
					return err
				},
			},
			&cli.StringFlag{
				Name:        "host",
				Usage:       "Listen on `HOST`",
				Aliases:     []string{"H"},
				EnvVars:     envvarNames("HOST"),
				Value:       "localhost",
				Destination: &proxyHost,
				Action: func(_ *cli.Context, h string) error {
					if h == "" {
						return errors.New("host cannot be empty")
					}
					return nil
				},
			},
			&cli.IntFlag{
				Name:        "port",
				Usage:       "Listen on `PORT`",
				Aliases:     []string{"p"},
				EnvVars:     envvarNames("PORT"),
				Value:       8443,
				Destination: &proxyPort,
				Action: func(_ *cli.Context, p int) error {
					if p < 1 || p > 65535 {
						return errors.New("port must be between 1 and 65535")
					}
					return nil
				},
			},
			&cli.PathFlag{
				Name:        "ssl-key-logfile",
				Usage:       "Log SSL Key information to `FILE`",
				EnvVars:     []string{"SSLKEYLOGFILE"},
				Destination: &sslLogfile,
			},
		},
		Action: func(cliCtx *cli.Context) error {
			ctx := cliCtx.Context
			cert, key, err := cafiles.GetCertKey(ctx, certUri, privKeyUri)
			if err != nil {
				return cli.Exit(fmt.Sprintf("Error reading cert/key: %s", err), 1)
			}

			clientCertPool := x509.NewCertPool()
			clientCertPool.AddCert(cert.Certificate)

			reverseProxy := &httputil.ReverseProxy{
				Rewrite: func(r *httputil.ProxyRequest) {
					r.SetURL(backendUrl)
					r.SetXForwarded()
				},
			}

			var ssllog *os.File
			if sslLogfile != "" {
				ssllog, err = os.OpenFile(
					sslLogfile,
					os.O_WRONLY|os.O_CREATE|os.O_APPEND,
					0o600,
				)
				if err != nil {
					return err
				}
				defer ssllog.Close()
			}

			hf := asgard.Hofund(asgard.HeaderNameClientCertLeaf, cert.Namespace)
			hdlr := sundry.RequestLogHandler(hf(reverseProxy))

			addr := fmt.Sprintf("%s:%d", proxyHost, proxyPort)
			serverCert, serverKey, err := cafiles.CreateServerCertificate(cert, key, 0)
			if err != nil {
				return cli.Exit(fmt.Sprintf("Error creating server certificate: %s", err), 1)
			}

			tlsCert, err := serverCert.ToTLSCertificate(*serverKey)
			if err != nil {
				return cli.Exit(fmt.Sprintf("Error converting server certificate: %s", err), 1)
			}

			server := http.Server{
				Handler: hdlr,
				Addr:    addr,
				TLSConfig: &tls.Config{
					Certificates: []tls.Certificate{*tlsCert},
					ClientAuth:   tls.RequireAndVerifyClientCert,
					ClientCAs:    clientCertPool,
					KeyLogWriter: ssllog,
				},
			}

			go func() {
				<-ctx.Done()
				ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
				defer cancel()
				if err := server.Shutdown(ctx); err != nil {
					panic(err)
				}
				slog.InfoContext(ctx, "shutting down server")
			}()

			slog.InfoContext(ctx, "proxying requests",
				"from", "https://"+addr,
				"to", backendUrl,
				"namespace", cert.Namespace.String(),
			)

			if err := server.ListenAndServeTLS("", ""); err != nil &&
				!errors.Is(err, http.ErrServerClosed) {
				return cli.Exit(fmt.Sprintf("Error starting server: %s", err), 1)
			}
			return nil
		},
	}
)
