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
	proxyCmd   = &cli.Command{
		Name:    "identity-proxy",
		Aliases: []string{"proxy", "id-proxy"},
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
				return cli.Exit(fmt.Sprintf("Error reading cert/key: %s", err), 1)
			}

			clientCertPool := x509.NewCertPool()
			clientCertPool.AddCert(caCert.Certificate)

			burl, err := url.Parse(backendUrl)
			if err != nil {
				return cli.Exit(fmt.Sprintf("Error parsing backend URL: %s", err), 1)
			}
			reverseProxy := &httputil.ReverseProxy{
				Rewrite: func(r *httputil.ProxyRequest) {
					r.SetURL(burl)
					r.SetXForwarded()
				},
			}

			var ssllog *os.File
			if sslLogfile != "" {
				ssllog, err = os.OpenFile(
					sslLogfile,
					os.O_WRONLY|os.O_CREATE|os.O_APPEND,
					0o600,
				)
				if err != nil {
					return err
				}
				defer ssllog.Close()
			}

			hf := asgard.Hofund(asgard.HeaderNameClientCertLeaf, caCert.Namespace)
			hdlr := webapp.RequestLogHandler(hf(reverseProxy))

			addr := fmt.Sprintf("%s:%d", proxyHost, proxyPort)
			serverKey, err := bifrost.NewPrivateKey()
			if err != nil {
				return cli.Exit(fmt.Sprintf("Error creating server key: %s", err), 1)
			}
			serverCert, err := issueTLSCert(caCert, caKey, serverKey)
			if err != nil {
				return cli.Exit(fmt.Sprintf("Error creating server certificate: %s", err), 1)
			}

			tlsCert, err := serverCert.ToTLSCertificate(*serverKey)
			if err != nil {
				return cli.Exit(fmt.Sprintf("Error converting server certificate: %s", err), 1)
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

			go func() {
				<-ctx.Done()
				ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
				defer cancel()
				if err := server.Shutdown(ctx); err != nil {
					panic(err)
				}
				slog.InfoContext(ctx, "shutting down server")
			}()

			slog.InfoContext(ctx, "proxying requests",
				"from", "https://"+addr,
				"to", backendUrl,
				"namespace", caCert.Namespace.String(),
			)

			if err := server.ListenAndServeTLS("", ""); err != nil &&
				!errors.Is(err, http.ErrServerClosed) {
				return cli.Exit(fmt.Sprintf("Error starting server: %s", err), 1)
			}
			return nil
		},
	}
)

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
