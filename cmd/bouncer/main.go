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
	"github.com/kelseyhightower/envconfig"
)

var spec = struct {
	config.Spec
	Port       int16  `default:"8080"`
	BackendUrl string `default:"http://127.0.0.1:8888"`
}{}

func main() {
	envconfig.MustProcess(config.Prefix, &spec)
	burl, err := url.Parse(spec.BackendUrl)
	if err != nil {
		log.Fatalf("error parsing backend url: %s", err)
	}

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

	clientCertPool := x509.NewCertPool()
	clientCertPool.AddCert(crt)

	addr := fmt.Sprintf("%s:%d", spec.Host, spec.Port)
	log.Printf("server listening on %s proxying requests to %s\n", addr, spec.BackendUrl)

	server := http.Server{
		Handler: httputil.NewSingleHostReverseProxy(burl),
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
