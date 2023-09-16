// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
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

	ns, crt, err := cafiles.GetCertificate(ctx, config.Issuer.CrtUri)
	sundry.OnErrorExit(ctx, err, "error getting crt")

	key, err := cafiles.GetPrivateKey(ctx, config.Issuer.KeyUri)
	sundry.OnErrorExit(ctx, err, "error getting key")

	ca, err := tinyca.New(crt, key, config.Issuer.Validity)
	sundry.OnErrorExit(ctx, err, "error creating ca")

	mux := http.NewServeMux()
	nss, _ := ns.MarshalText()
	mux.HandleFunc("/namespace", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write(nss)
	})
	mux.Handle("/issue", ca)
	mux.HandleFunc("/metrics", stats.MetricsHandler)

	if w := config.Issuer.Web; w.Serve {
		if w.LocalFiles {
			slog.DebugCtx(ctx, "serving web from local filesystem")
			mux.Handle("/", http.FileServer(http.Dir("web")))
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
		slog.String("ca", ca.String()),
	)

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		sundry.OnErrorExit(ctx, err, "error serving requests")
	}
}
