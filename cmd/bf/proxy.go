package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"time"

	"github.com/RealImage/bifrost"
	"github.com/RealImage/bifrost/asgard"
	"github.com/RealImage/bifrost/cafiles"
	"github.com/RealImage/bifrost/internal/webapp"
	"github.com/RealImage/bifrost/tinyca"
	"github.com/urfave/cli/v3"
)

var (
	backendUrl string
	proxyHost  string
	proxyPort  int64
	sslLogfile string
)

var proxyCmd = &cli.Command{
	Name:    "identity-proxy",
	Aliases: []string{"proxy", "id-proxy"},
	Usage:   "Proxies mTLS requests to a backend server",
	Flags: []cli.Flag{
		caCertFlag,
		caPrivKeyFlag,
		&cli.StringFlag{
			Name:        "backend-url",
			Usage:       "Proxy requests to `URL`",
			Aliases:     []string{"b"},
			Value:       "http://localhost:8080",
			Destination: &backendUrl,
		},
		&cli.StringFlag{
			Name:        "host",
			Usage:       "Listen on `HOST`",
			Aliases:     []string{"H"},
			Sources:     cli.EnvVars("HOST"),
			Value:       "localhost",
			Destination: &proxyHost,
			Action: func(_ context.Context, _ *cli.Command, h string) error {
				if h == "" {
					return errors.New("host cannot be empty")
				}
				return nil
			},
		},
		&cli.IntFlag{
			Name:        "port",
			Usage:       "Listen on `PORT`",
			Aliases:     []string{"p"},
			Sources:     cli.EnvVars("PORT"),
			Value:       8443,
			Destination: &proxyPort,
			Action: func(_ context.Context, _ *cli.Command, p int64) error {
				if p < 1 || p > 65535 {
					return errors.New("port must be between 1 and 65535")
				}
				return nil
			},
		},
		&cli.StringFlag{
			Name:        "ssl-key-logfile",
			Usage:       "Log SSL Key information to `FILE`",
			Sources:     cli.EnvVars("SSLKEYLOGFILE"),
			Destination: &sslLogfile,
		},
	},
	Action: func(ctx context.Context, _ *cli.Command) error {
		caCert, caKey, err := cafiles.GetCertKey(ctx, caCertUri, caPrivKeyUri)
		if err != nil {
			slog.ErrorContext(ctx, "error reading cert/key", "error", err)
			return cli.Exit("Error reading certificate/private key", 1)
		}

		// Create a client certificate pool and add the CA certificate.
		clientCertPool := x509.NewCertPool()
		clientCertPool.AddCert(caCert.Certificate)

		burl, err := url.Parse(backendUrl)
		if err != nil {
			slog.ErrorContext(ctx, "error parsing backend url", "error", err)
			return cli.Exit("Error parsing backend URL", 1)
		}
		reverseProxy := &httputil.ReverseProxy{
			Rewrite: func(r *httputil.ProxyRequest) {
				r.SetURL(burl)
				r.SetXForwarded()
			},
		}

		var ssllog *os.File
		if sslLogfile != "" {
			if ssllog, err = os.OpenFile(
				sslLogfile,
				os.O_WRONLY|os.O_CREATE|os.O_APPEND,
				0o600,
			); err != nil {
				return err
			}
			defer ssllog.Close()
		}

		hf := asgard.Hofund(asgard.HeaderNameClientCertLeaf, caCert.Namespace)
		hdlr := webapp.RequestLogger(hf(reverseProxy))

		addr := fmt.Sprintf("%s:%d", proxyHost, proxyPort)
		serverKey, err := bifrost.NewPrivateKey()
		if err != nil {
			slog.ErrorContext(ctx, "error creating key", "error", err)
			return cli.Exit("Error creating server key", 1)
		}

		serverCert, err := issueTLSCert(caCert, caKey, serverKey)
		if err != nil {
			slog.ErrorContext(ctx, "error creating certificate", "error", err)
			return cli.Exit("Error creating server certificate", 1)
		}

		tlsCert, err := serverCert.ToTLSCertificate(*serverKey)
		if err != nil {
			slog.ErrorContext(ctx, "error converting certificate", "error", err)
			return cli.Exit("Certificate error", 1)
		}

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

		slog.InfoContext(ctx, "proxying requests",
			"from", "https://"+addr,
			"to", backendUrl,
			"namespace", caCert.Namespace.String(),
		)

		go func() {
			if err := server.ListenAndServeTLS("", ""); err != nil &&
				!errors.Is(err, http.ErrServerClosed) {
				slog.ErrorContext(ctx, "error starting server", "error", err)
				os.Exit(1)
			}
		}()

		ctx, cancel := signal.NotifyContext(ctx, os.Interrupt)
		defer cancel()

		<-ctx.Done()

		ctx, cancel = context.WithTimeout(context.Background(), time.Second*5)
		defer cancel()

		if err := server.Shutdown(ctx); err != nil {
			return err
		}
		slog.InfoContext(ctx, "shut down server")

		return nil
	},
}

func issueTLSCert(
	caCert *bifrost.Certificate,
	caKey, serverKey *bifrost.PrivateKey,
) (*bifrost.Certificate, error) {
	gauntlet := func(_ context.Context, _ *bifrost.CertificateRequest) (*x509.Certificate, error) {
		// Return a server certificate template that can be used for TLS.
		return &x509.Certificate{
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
		}, nil
	}
	ca, err := tinyca.New(caCert, caKey, gauntlet)
	if err != nil {
		return nil, err
	}
	defer ca.Close()

	caNs := caCert.Namespace
	csr := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   serverKey.UUID(caNs).String(),
			Organization: []string{caNs.String()},
		},
		SignatureAlgorithm: bifrost.SignatureAlgorithm,
		DNSNames:           []string{"localhost"},
		IPAddresses:        []net.IP{net.ParseIP("127.0.0.0")},
	}
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &csr, serverKey)
	if err != nil {
		return nil, fmt.Errorf("error creating certificate request: %w", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.AddDate(0, 0, 15)

	certBytes, err := ca.IssueCertificate(csrBytes, notBefore, notAfter)
	if err != nil {
		return nil, fmt.Errorf("error issuing server certificate: %w", err)
	}

	cert, err := bifrost.ParseCertificate(certBytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing server certificate: %w", err)
	}
	return cert, nil
}
