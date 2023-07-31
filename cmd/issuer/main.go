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
	"time"

	"github.com/RealImage/bifrost/internal/cafiles"
	"github.com/RealImage/bifrost/internal/config"
	"github.com/RealImage/bifrost/internal/stats"
	"github.com/RealImage/bifrost/internal/sundry"
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

	_, crt, err := cafiles.GetCertificate(ctx, config.Issuer.CrtUri)
	sundry.OnErrorExit(ctx, err, "error getting crt")

	key, err := cafiles.GetPrivateKey(ctx, config.Issuer.KeyUri)
	sundry.OnErrorExit(ctx, err, "error getting key")

	ca, err := tinyca.New(crt, key, config.Issuer.IssueDuration)
	sundry.OnErrorExit(ctx, err, "error creating ca")

	mux := http.NewServeMux()
	mux.Handle("/issue", ca)
	mux.HandleFunc("/metrics", stats.MetricsHandler)

	server := http.Server{Addr: config.Issuer.Address, Handler: mux}
	server.BaseContext = func(_ net.Listener) context.Context {
		return ctx
	}
	go func() {
		<-ctx.Done()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
		defer cancel()
		slog.InfoCtx(ctx, "shutting down server")
		if err := server.Shutdown(ctx); err != nil {
			panic(err)
		}
	}()

	slog.InfoCtx(ctx, "serving requests",
		slog.String("address", config.Issuer.Address),
		slog.String("ca", ca.String()),
	)

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		sundry.OnErrorExit(ctx, err, "error serving requests")
	}
}
