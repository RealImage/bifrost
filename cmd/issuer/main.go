package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/RealImage/bifrost"
	"github.com/RealImage/bifrost/internal/cafiles"
	"github.com/google/uuid"
	"github.com/kelseyhightower/envconfig"
)

var spec = struct {
	Host           string    `default:"127.0.0.1"`
	Port           int16     `default:"7777"`
	MetricsPushUrl string    `envconfig:"METRICS_PUSH_URL"`
	CrtUri         string    `envconfig:"CRT_URI" default:"crt.pem"`
	KeyUri         string    `envconfig:"KEY_URI" default:"key.pem"`
	IDNamespace    uuid.UUID `envconfig:"BFID_NAMESPACE"`
}{}

func main() {
	envconfig.MustProcess("", &spec)

	crt, err := cafiles.GetCrtUri(spec.CrtUri)
	if err != nil {
		log.Fatalf("error getting crt: %s", err)
	}

	key, err := cafiles.GetKeyUri(spec.KeyUri)
	if err != nil {
		log.Fatalf("error getting key: %s", err)
	}

	if url := spec.MetricsPushUrl; url != "" {
		pushInterval := time.Second * 15
		log.Printf("pushing metrics to %s every %.2fs\n", url, pushInterval.Seconds())
		if err := bifrost.Metrics.InitPush(url, pushInterval, ""); err != nil {
			log.Fatalf("error setting up metrics push: %s\n", err)
		}
	}

	ca := bifrost.CA{
		Crt:               crt,
		Key:               key,
		IdentityNamespace: spec.IDNamespace,
	}

	address := fmt.Sprintf("%s:%d", spec.Host, spec.Port)
	log.Printf("server listening on %s\n", address)
	http.Handle("/", ca)
	http.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		bifrost.Metrics.WritePrometheus(w)
	})

	if err := http.ListenAndServe(address, nil); err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
