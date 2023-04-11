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
	"github.com/RealImage/bifrost/pkg/tinyca"
	"github.com/kelseyhightower/envconfig"
	"golang.org/x/exp/slog"
)

var spec = struct {
	config.Spec
	Address       string        `envconfig:"ADDR" default:"127.0.0.1:8888"`
	IssueDuration time.Duration `envconfig:"ISSUE_DUR" default:"1h"`
}{}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	envconfig.MustProcess(config.Prefix, &spec)
	config.Log(spec.LogLevel)
	sha, timestamp := config.GetBuildInfo()
	slog.InfoCtx(ctx, "build info", "sha", sha, "timestamp", timestamp)

	crt, err := cafiles.GetCertificate(ctx, spec.CrtUri)
	if err != nil {
		slog.ErrorCtx(ctx, "error getting crt", "err", err)
		os.Exit(1)
	}

	key, err := cafiles.GetPrivateKey(ctx, spec.KeyUri)
	if err != nil {
		slog.ErrorCtx(ctx, "error getting key", "err", err)
		os.Exit(1)
	}

	ca := tinyca.New(spec.Namespace, crt, key, spec.IssueDuration)

	slog.Info("serving requests", "listen", spec.Address, "ca", ca)

	mux := http.NewServeMux()
	mux.Handle("/issue", ca)
	mux.HandleFunc("/metrics", stats.MetricsHandler)

	server := http.Server{Addr: spec.Address, Handler: mux}
	server.BaseContext = func(_ net.Listener) context.Context {
		return ctx
	}
	go func() {
		<-ctx.Done()
		slog.Info("shutting down server")
		if err := server.Shutdown(ctx); err != nil {
			panic(err)
		}
	}()
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		slog.ErrorCtx(ctx, "error serving", "err", err)
		os.Exit(1)
	}
}
