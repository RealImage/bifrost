package main

import (
	"context"
	"fmt"
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
	Port           int16  `default:"7777"`
	MetricsPushUrl string `envconfig:"METRICS_PUSH_URL"`
}{}

func main() {
	envconfig.MustProcess(config.Prefix, &spec)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	crt, err := cafiles.GetCertificate(ctx, spec.CrtUri)
	if err != nil {
		log.Fatalf("error getting crt: %s", err)
	}

	key, err := cafiles.GetPrivateKey(ctx, spec.KeyUri)
	if err != nil {
		log.Fatalf("error getting key: %s", err)
	}

	if url := spec.MetricsPushUrl; url != "" {
		pushInterval := time.Second * 15
		log.Printf("pushing metrics to %s every %.2fs\n", url, pushInterval.Seconds())
		if err := stats.ForNerds.InitPush(url, pushInterval, ""); err != nil {
			log.Fatalf("error setting up metrics push: %s\n", err)
		}
	}

	ca := tinyca.CA{
		Crt:               crt,
		Key:               key,
		IdentityNamespace: spec.IDNamespace,
	}

	address := fmt.Sprintf("%s:%d", spec.Host, spec.Port)
	log.Printf("server listening on %s\n", address)
	http.Handle("/", ca)
	http.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		stats.ForNerds.WritePrometheus(w)
	})

	if err := http.ListenAndServe(address, nil); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
