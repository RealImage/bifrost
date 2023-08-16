package bifrost

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"time"
)

// HTTPClient returns a http.Client set up for TLS Client Authentication (mTLS).
// If roots is not nil, then only those Root CAs are used to authenticate server certs.
// If ssllog is not nil, the client will log TLS key material to it.
func HTTPClient(clientCert tls.Certificate, roots *x509.CertPool, ssllog io.Writer) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{clientCert},
				RootCAs:      roots,
				KeyLogWriter: ssllog,
			},
		},
	}
}
