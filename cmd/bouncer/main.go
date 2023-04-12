// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"

	"github.com/RealImage/bifrost"
	"github.com/RealImage/bifrost/internal/cafiles"
	"github.com/RealImage/bifrost/internal/config"
	"github.com/RealImage/bifrost/pkg/club"
	"github.com/kelseyhightower/envconfig"
	"golang.org/x/exp/slog"
)

var spec = struct {
	config.Spec
	Address    string `envconfig:"ADDR" default:"localhost:8443"`
	BackendUrl string `envconfig:"BACKEND" default:"http://localhost:8080"`
}{}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	envconfig.MustProcess(config.Prefix, &spec)
	config.Log(spec.LogLevel)
	sha, timestamp := config.GetBuildInfo()
	slog.InfoCtx(ctx, "build info", "sha", sha, "timestamp", timestamp)

	backendUrl, err := url.Parse(spec.BackendUrl)
	if err != nil {
		slog.ErrorCtx(ctx, "error parsing backend url", "err", err)
		os.Exit(1)
	}

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

	clientCertPool := x509.NewCertPool()
	clientCertPool.AddCert(crt)

	slog.InfoCtx(
		ctx,
		"proxying requests",
		slog.String("from", "https://"+spec.Address),
		slog.String("to", spec.BackendUrl),
	)

	reverseProxy := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(backendUrl)
			r.SetXForwarded()
		},
	}
	server := http.Server{
		Handler: club.Bouncer(reverseProxy),
		Addr:    spec.Address,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{*bifrost.X509ToTLSCertificate(crt, key)},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    clientCertPool,
		},
	}
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
	if err := server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
		slog.ErrorCtx(ctx, "error servinc requests", "err", err)
		os.Exit(1)
	}
}
