package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
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
	Port        int16  `default:"8080"`
	BackendUrl  string `default:"http://localhost:8888"`
	MetricsHost string `envconfig:"METRICS_HOST" default:"localhost"`
	MetricsPort int16  `envconfig:"METRICS_PORT" default:"8989"`
}{}

func main() {
	envconfig.MustProcess(config.Prefix, &spec)
	if sha, timestamp, ok := config.GetBuildInfo(); ok {
		log.Printf("commit sha: %s, timestamp %s", sha, timestamp)
	}
	stats.MaybePushMetrics(spec.MetricsPushUrl, spec.MetricsPushInterval)
	go serveMetrics(spec.MetricsHost, spec.MetricsPort)

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

	addr := fmt.Sprintf("%s:%d", spec.Host, spec.Port)
	log.Printf("server listening on %s proxying requests to %s\n", addr, spec.BackendUrl)

	reverseProxy := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(backendUrl)
			r.SetXForwarded()
		},
	}
	server := http.Server{
		Handler: club.Bouncer(reverseProxy),
		Addr:    fmt.Sprintf("%s:%d", spec.Host, spec.Port),
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

func serveMetrics(host string, port int16) {
	srv := http.Server{
		Addr:    fmt.Sprintf("%s:%d", host, port),
		Handler: http.HandlerFunc(stats.MetricsHandler),
	}
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Printf("error starting metrics server: %s\n", err)
	}
}
