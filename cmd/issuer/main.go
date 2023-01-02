package main

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/RealImage/bifrost/internal/cafiles"
	"github.com/RealImage/bifrost/internal/config"
	"github.com/RealImage/bifrost/internal/stats"
	"github.com/RealImage/bifrost/pkg/tinyca"
	"github.com/kelseyhightower/envconfig"
)

var spec = struct {
	config.Spec
	Port int16 `default:"7777"`
}{}

func main() {
	envconfig.MustProcess(config.Prefix, &spec)
	if sha, timestamp, ok := config.GetBuildInfo(); ok {
		log.Println("commit sha: ", sha)
		log.Println("commit time: ", timestamp)
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

	ca := tinyca.CA{
		Crt:               crt,
		Key:               key,
		IdentityNamespace: spec.Namespace,
	}

	address := fmt.Sprintf("%s:%d", spec.Host, spec.Port)
	log.Printf("server listening on %s\n", address)

	mux := http.NewServeMux()
	mux.Handle("/", ca)
	mux.HandleFunc("/metrics", stats.MetricsHandler)
	srv := http.Server{Addr: address, Handler: mux}
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
