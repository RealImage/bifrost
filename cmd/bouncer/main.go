// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"time"

	"github.com/RealImage/bifrost"
	"github.com/RealImage/bifrost/internal/cafiles"
	"github.com/RealImage/bifrost/internal/config"
	"github.com/RealImage/bifrost/internal/stats"
	"github.com/RealImage/bifrost/internal/sundry"
	"github.com/RealImage/bifrost/pkg/asgard"
	"github.com/kelseyhightower/envconfig"
	"golang.org/x/exp/slog"
)

func main() {
	envconfig.MustProcess(config.EnvPrefix, &config.Bouncer)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	slog.InfoCtx(
		ctx, "build info",
		slog.String("rev", config.BuildRevision),
		slog.Time("timestamp", config.BuildTime),
	)

	if config.Bouncer.MetricsUrl != "" {
		http.HandleFunc("/", stats.MetricsHandler)
		go func() {
			if err := http.ListenAndServe(config.Bouncer.MetricsUrl, nil); err != nil {
				panic(err)
			}
		}()
	}

	backendUrl, err := url.Parse(config.Bouncer.BackendUrl)
	sundry.OnErrorExit(ctx, err, "error parsing backend url")

	ns, crt, err := cafiles.GetCertificate(ctx, config.Bouncer.CrtUri)
	sundry.OnErrorExit(ctx, err, "error getting crt")

	key, err := cafiles.GetPrivateKey(ctx, config.Bouncer.KeyUri)
	sundry.OnErrorExit(ctx, err, "error getting key")

	clientCertPool := x509.NewCertPool()
	clientCertPool.AddCert(crt)

	reverseProxy := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(backendUrl)
			r.SetXForwarded()
		},
	}

	var ssllog *os.File
	if config.Bouncer.SSLKeyLogFile != "" {
		ssllog, err = os.OpenFile(
			config.Bouncer.SSLKeyLogFile,
			os.O_WRONLY|os.O_CREATE|os.O_APPEND,
			0o600,
		)
		sundry.OnErrorExit(ctx, err, "error opening ssl key log file")
		defer ssllog.Close()
	}

	id := asgard.Identify(asgard.DefaultRequestContextHeader)
	hdlr := sundry.RequestLogHandler(id(reverseProxy))
	addr := fmt.Sprintf("%s:%d", config.Bouncer.Host, config.Bouncer.Port)
	server := http.Server{
		Handler: hdlr,
		Addr:    addr,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{*bifrost.X509ToTLSCertificate(crt, key)},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    clientCertPool,
			KeyLogWriter: ssllog,
		},
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

	slog.InfoCtx(ctx, "proxying requests",
		"from", "https://"+addr,
		"to", config.Bouncer.BackendUrl,
		"ns", ns.String(),
	)

	if err := server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
		sundry.OnErrorExit(ctx, err, "error serving requests")
	}
}
