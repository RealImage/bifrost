package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/RealImage/bifrost"
	"github.com/RealImage/bifrost/internal/cafiles"
	"github.com/RealImage/bifrost/internal/config"
	"github.com/RealImage/bifrost/internal/stats"
	"github.com/RealImage/bifrost/pkg/club"
	"github.com/kelseyhightower/envconfig"
)

var spec = struct {
	config.Spec
	Address    string `envconfig:"ADDR" default:"localhost:8787"`
	BackendUrl string `envconfig:"BACKEND" default:"http://localhost:8080"`
}{}

func main() {
	envconfig.MustProcess(config.Prefix, &spec)
	if sha, timestamp, ok := config.GetBuildInfo(); ok {
		log.Printf("commit sha: %s, timestamp %s", sha, timestamp)
	}
	stats.MaybePushMetrics(spec.MetricsPushUrl, spec.MetricsPushInterval)

	backendUrl, err := url.Parse(spec.BackendUrl)
	if err != nil {
		log.Fatalf("error parsing backend url: %s\n", err)
	}

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

	clientCertPool := x509.NewCertPool()
	clientCertPool.AddCert(crt)

	log.Printf("server listening on %s proxying requests to %s\n", spec.Address, spec.BackendUrl)

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
	if err := server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
