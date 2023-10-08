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

	"github.com/RealImage/bifrost/internal/cafiles"
	"github.com/RealImage/bifrost/internal/config"
	"github.com/RealImage/bifrost/internal/middleware"
	"github.com/RealImage/bifrost/internal/stats"
	"github.com/RealImage/bifrost/internal/sundry"
	"github.com/kelseyhightower/envconfig"
	"golang.org/x/exp/slog"
)

func main() {
	envconfig.MustProcess(config.EnvPrefix, &config.HallPass)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	slog.InfoCtx(
		ctx, "build info",
		slog.String("rev", config.BuildRevision),
		slog.Time("timestamp", config.BuildTime),
	)

	if config.HallPass.MetricsUrl != "" {
		http.HandleFunc("/", stats.MetricsHandler)
		go func() {
			if err := http.ListenAndServe(config.HallPass.MetricsUrl, nil); err != nil {
				panic(err)
			}
		}()
	}

	backendUrl, err := url.Parse(config.HallPass.BackendUrl)
	sundry.OnErrorExit(ctx, err, "error parsing backend url")

	cert, key, err := cafiles.GetCertKey(ctx, config.HallPass.CrtUri, config.HallPass.KeyUri)
	sundry.OnErrorExit(ctx, err, "error getting cert and key")

	clientCertPool := x509.NewCertPool()
	clientCertPool.AddCert(cert.Certificate)

	reverseProxy := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(backendUrl)
			r.SetXForwarded()
		},
	}

	var ssllog *os.File
	if config.HallPass.SSLKeyLogFile != "" {
		ssllog, err = os.OpenFile(
			config.HallPass.SSLKeyLogFile,
			os.O_WRONLY|os.O_CREATE|os.O_APPEND,
			0o600,
		)
		sundry.OnErrorExit(ctx, err, "error opening ssl key log file")
		defer ssllog.Close()
	}

	ti := middleware.TLSIdentifier(middleware.RequestContextHeaderName, cert.Namespace)
	hdlr := sundry.RequestLogHandler(ti(reverseProxy))

	addr := fmt.Sprintf("%s:%d", config.HallPass.Host, config.HallPass.Port)
	serverCert, serverKey, err := cafiles.CreateServerCertificate(cert, key)
	sundry.OnErrorExit(ctx, err, "error creating server certificate")
	tlsCert, err := serverCert.ToTLSCertificate(serverKey)
	sundry.OnErrorExit(ctx, err, "error creating tls certificate")

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
		ctx, cancel := context.WithTimeout(context.Background(), config.HallPass.ShutdownTimeout)
		defer cancel()
		slog.InfoCtx(ctx, "shutting down server")
		if err := server.Shutdown(ctx); err != nil {
			panic(err)
		}
	}()

	slog.InfoCtx(ctx, "proxying requests",
		"from", "https://"+addr,
		"to", config.HallPass.BackendUrl,
		"namespace", cert.Namespace.String(),
	)

	if err := server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
		sundry.OnErrorExit(ctx, err, "error serving requests")
	}
}