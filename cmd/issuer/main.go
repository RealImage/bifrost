// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"

	"github.com/RealImage/bifrost/internal/cafiles"
	"github.com/RealImage/bifrost/internal/config"
	"github.com/RealImage/bifrost/internal/stats"
	"github.com/RealImage/bifrost/internal/sundry"
	"github.com/RealImage/bifrost/internal/webapp"
	"github.com/RealImage/bifrost/tinyca"
	"github.com/kelseyhightower/envconfig"
	"golang.org/x/exp/slog"
)

func main() {
	envconfig.MustProcess(config.EnvPrefix, &config.Issuer)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	slog.InfoCtx(
		ctx, "build info",
		slog.String("rev", config.BuildRevision),
		slog.Time("timestamp", config.BuildTime),
	)

	cert, key, err := cafiles.GetCertKey(ctx, config.Issuer.CrtUri, config.Issuer.KeyUri)
	sundry.OnErrorExit(ctx, err, "error getting cert and key")

	mux := http.NewServeMux()

	if config.Issuer.Metrics {
		slog.DebugCtx(ctx, "metrics enabled")
		mux.HandleFunc("/metrics", stats.MetricsHandler)
	}

	ca, err := tinyca.New(cert, key, config.Issuer.Validity)
	sundry.OnErrorExit(ctx, err, "error creating ca")
	mux.Handle("/issue", ca)

	nss := cert.Namespace.String()
	mux.HandleFunc("/namespace", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, nss)
	})

	if w := config.Issuer.Web; w.Enabled {
		slog.DebugCtx(ctx, "web enabled", "staticFiles", w.StaticFilesPath)
		webapp.AddRoutes(mux, w.StaticFilesPath, cert.Namespace)
	}

	hdlr := sundry.RequestLogHandler(mux)
	addr := fmt.Sprintf("%s:%d", config.Issuer.Host, config.Issuer.Port)
	server := http.Server{Addr: addr, Handler: hdlr}

	go func() {
		<-ctx.Done()
		ctx, cancel := context.WithTimeout(context.Background(), config.Issuer.ShutdownTimeout)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			panic(err)
		}
		slog.InfoCtx(ctx, "shutting down server")
	}()

	slog.InfoCtx(ctx, "serving requests", "address", addr, "namespace", cert.Namespace)

	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		sundry.OnErrorExit(ctx, err, "error serving requests")
	}
}
