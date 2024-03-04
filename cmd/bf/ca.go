package main

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/RealImage/bifrost/cafiles"
	"github.com/RealImage/bifrost/internal/webapp"
	"github.com/RealImage/bifrost/tinyca"
	"github.com/urfave/cli/v2"
)

var (
	caHost        string
	caPort        int
	webEnabled    bool
	webStaticPath string
	exposeMetrics bool
	caCmd         = &cli.Command{
		Name:    "certificate-authority",
		Aliases: []string{"ca"},
		Flags: []cli.Flag{
			caCertFlag,
			caPrivKeyFlag,
			&cli.StringFlag{
				Name:        "host",
				Usage:       "listen on `HOST`",
				Aliases:     []string{"H"},
				EnvVars:     []string{"HOST"},
				Value:       "localhost",
				Destination: &caHost,
				Action: func(_ *cli.Context, h string) error {
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
				EnvVars:     []string{"PORT"},
				Value:       8008,
				Destination: &caPort,
				Action: func(_ *cli.Context, p int) error {
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
				EnvVars:     []string{"WEB"},
				Destination: &webEnabled,
			},
			&cli.PathFlag{
				Name:        "web-static-path",
				Usage:       "read web static files from `PATH`",
				EnvVars:     []string{"WEB_STATIC_PATH"},
				Destination: &webStaticPath,
			},
			&cli.BoolFlag{
				Name:        "metrics",
				Usage:       "expose Prometheus metrics",
				EnvVars:     []string{"METRICS"},
				Value:       false,
				Destination: &exposeMetrics,
			},
		},

		Action: func(cliCtx *cli.Context) error {
			ctx := cliCtx.Context
			cert, key, err := cafiles.GetCertKey(ctx, caCertUri, caPrivKeyUri)
			if err != nil {
				return cli.Exit(fmt.Sprintf("Error reading cert/key: %s", err), 1)
			}

			mux := http.NewServeMux()

			if exposeMetrics {
				slog.DebugContext(ctx, "metrics enabled")
				mux.HandleFunc("GET /metrics", webapp.MetricsHandler)
			}

			ca, err := tinyca.New(cert, key)
			if err != nil {
				return cli.Exit(fmt.Sprintf("Error creating CA: %s", err), 1)
			}

			mux.Handle("POST /issue", ca)

			nss := cert.Namespace.String()
			mux.HandleFunc("GET /namespace", func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, nss)
			})

			if webEnabled {
				slog.DebugContext(ctx, "web enabled", "staticFiles", webStaticPath)
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
)
