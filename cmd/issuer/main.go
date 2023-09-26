// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/RealImage/bifrost/internal/cafiles"
	"github.com/RealImage/bifrost/internal/config"
	"github.com/RealImage/bifrost/internal/stats"
	"github.com/RealImage/bifrost/internal/sundry"
	"github.com/RealImage/bifrost/pkg/tinyca"
	"github.com/RealImage/bifrost/web"
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

	crtsKeys, err := cafiles.GetCrtsKeys(ctx, config.Issuer.CrtUris, config.Issuer.KeyUris)
	sundry.OnErrorExit(ctx, err, "error getting crts and keys")

	mux := http.NewServeMux()

	if config.Issuer.Metrics {
		mux.HandleFunc("/metrics", stats.MetricsHandler)
	}

	var namespaces bytes.Buffer
	for _, c := range crtsKeys {
		ca, err := tinyca.New(c.Crt, c.Key, config.Issuer.Validity)
		sundry.OnErrorExit(ctx, err, "error creating ca")

		nss := c.Ns.String()
		namespaces.WriteString(nss)
		namespaces.WriteString("\n")
		mux.Handle(fmt.Sprintf("/%s/issue", nss), ca)
	}

	mux.HandleFunc("/namespaces", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write(namespaces.Bytes())
	})

	if w := config.Issuer.Web; w.Serve {
		if w.LocalFiles {
			slog.DebugCtx(ctx, "serving web from local filesystem")
			mux.Handle("/", http.FileServer(http.Dir("web/static")))
		} else {
			slog.DebugCtx(ctx, "serving web from embedded filesystem")
			mux.Handle("/", http.FileServer(http.FS(web.Static)))
		}
	}

	hdlr := sundry.RequestLogHandler(mux)

	addr := fmt.Sprintf("%s:%d", config.Issuer.Host, config.Issuer.Port)

	server := http.Server{Addr: addr, Handler: hdlr}
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
		slog.String("address", addr),
		slog.Any("namespaces", namespaces),
	)

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		sundry.OnErrorExit(ctx, err, "error serving requests")
	}
}
