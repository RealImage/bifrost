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
	ca            = &cli.Command{
		Name:    "certificate-authority",
		Aliases: []string{"ca"},
		Flags: []cli.Flag{
			certFlag,
			keyFlag,
			issueValidFlag,
			&cli.StringFlag{
				Name:        "host",
				Usage:       "listen on `HOST`",
				Aliases:     []string{"H"},
				EnvVars:     envvarNames("HOST"),
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
				EnvVars:     envvarNames("PORT"),
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
				EnvVars:     envvarNames("WEB"),
				Destination: &webEnabled,
			},
			&cli.PathFlag{
				Name:        "web-static-path",
				Usage:       "read web static files from `PATH`",
				EnvVars:     envvarNames("WEB_STATIC_PATH"),
				Destination: &webStaticPath,
			},
			&cli.BoolFlag{
				Name:        "metrics",
				Usage:       "expose Prometheus metrics",
				EnvVars:     envvarNames("METRICS"),
				Value:       false,
				Destination: &exposeMetrics,
			},
		},

		Action: func(cliCtx *cli.Context) error {
			ctx := cliCtx.Context
			cert, key, err := cafiles.GetCertKey(ctx, certUri, privKeyUri)
			if err != nil {
				return cli.Exit(fmt.Sprintf("Error reading cert/key: %s", err), 1)
			}

			mux := http.NewServeMux()

			if exposeMetrics {
				slog.DebugContext(ctx, "metrics enabled")
				mux.HandleFunc("/metrics", webapp.MetricsHandler)
			}

			ca, err := tinyca.New(cert, key, issueValidity)
			if err != nil {
				return cli.Exit(fmt.Sprintf("Error creating CA: %s", err), 1)
			}

			mux.Handle("/issue", ca)

			nss := cert.Namespace.String()
			mux.HandleFunc("/namespace", func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, nss)
			})

			if webEnabled {
				slog.DebugContext(ctx, "web enabled", "staticFiles", webStaticPath)
				webapp.AddRoutes(mux, webStaticPath, cert.Namespace)
			}

			hdlr := webapp.RequestLogHandler(mux)

			addr := fmt.Sprintf("%s:%d", caHost, caPort)
			slog.InfoContext(ctx, "starting server", "addr", addr)

			server := http.Server{Addr: addr, Handler: hdlr}
			if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				return cli.Exit(fmt.Sprintf("Error starting server: %s", err), 1)
			}

			return nil
		},
	}
)