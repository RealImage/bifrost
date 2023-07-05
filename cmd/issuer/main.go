// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"context"
	"net"
	"net/http"
	"os"
	"os/signal"

	"github.com/RealImage/bifrost/internal/cafiles"
	"github.com/RealImage/bifrost/internal/config"
	"github.com/RealImage/bifrost/internal/stats"
	"github.com/RealImage/bifrost/pkg/tinyca"
	"github.com/kelseyhightower/envconfig"
	"golang.org/x/exp/slog"
)

func main() {
	envconfig.MustProcess(config.EnvPrefix, &config.Issuer)
	config.LogLevel.Set(config.Issuer.LogLevel)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	sha, timestamp := config.CommitInfo()
	slog.InfoCtx(ctx, "build info", slog.String("sha", sha), slog.Any("timestamp", timestamp))

	crt, err := cafiles.GetCertificate(ctx, config.Issuer.CrtUri)
	if err != nil {
		slog.ErrorCtx(ctx, "error getting crt", "err", err)
		os.Exit(1)
	}

	key, err := cafiles.GetPrivateKey(ctx, config.Issuer.KeyUri)
	if err != nil {
		slog.ErrorCtx(ctx, "error getting key", "err", err)
		os.Exit(1)
	}

	ca := tinyca.New(config.Issuer.Namespace, crt, key, config.Issuer.IssueDuration)

	slog.InfoCtx(
		ctx,
		"serving requests",
		slog.String("listen", config.Issuer.Address),
		slog.String("ca", ca.String()),
	)

	mux := http.NewServeMux()
	mux.Handle("/issue", ca)
	mux.HandleFunc("/metrics", stats.MetricsHandler)

	server := http.Server{Addr: config.Issuer.Address, Handler: mux}
	server.BaseContext = func(_ net.Listener) context.Context {
		return ctx
	}
	go func() {
		<-ctx.Done()
		slog.InfoCtx(ctx, "shutting down server")
		if err := server.Shutdown(ctx); err != nil {
			panic(err)
		}
	}()
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		slog.ErrorCtx(ctx, "error serving", "err", err)
		os.Exit(1)
	}
}
