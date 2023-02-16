package main

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/RealImage/bifrost/internal/cafiles"
	"github.com/RealImage/bifrost/internal/config"
	"github.com/RealImage/bifrost/internal/stats"
	"github.com/RealImage/bifrost/pkg/tinyca"
	"github.com/kelseyhightower/envconfig"
)

var spec = struct {
	config.Spec
	Address       string        `envconfig:"ADDR" default:"127.0.0.1:8888"`
	IssueDuration time.Duration `envconfig:"ISSUE_DUR" default:"1h"`
}{}

func main() {
	envconfig.MustProcess(config.Prefix, &spec)
	if sha, timestamp, ok := config.GetBuildInfo(); ok {
		log.Printf("commit sha: %s, timestamp %s", sha, timestamp)
	}
	stats.MaybePushMetrics(spec.MetricsPushUrl, spec.MetricsPushInterval)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	crt, err := cafiles.GetCertificate(ctx, spec.CrtUri)
	if err != nil {
		log.Fatalf("error getting crt: %s\n", err)
	}

	key, err := cafiles.GetPrivateKey(ctx, spec.KeyUri)
	if err != nil {
		log.Fatalf("error getting key: %s\n", err)
	}

	ca := tinyca.New(spec.Namespace, crt, key, spec.IssueDuration)

	log.Printf("%s listening on %s\n", ca, spec.Address)

	mux := http.NewServeMux()
	mux.Handle("/", ca)
	mux.HandleFunc("/metrics", stats.MetricsHandler)
	srv := http.Server{Addr: spec.Address, Handler: mux}
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
