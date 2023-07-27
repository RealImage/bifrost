package bifrost

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"time"
)

// HTTPClient returns a http.Client configured for mTLS with client authentication.
// The client will use the provided Hosts map to map hostnames to backend URLs.
// Client certificates are loaded from clientCert and rootCAs is used to
// validate the server certificate.
// If ssllog is not nil, the client will log TLS key material to it.
func HTTPClient(
	clientCert *tls.Certificate,
	rootCAs *x509.CertPool,
	ssllog io.Writer,
) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			TLSClientConfig: &tls.Config{
				GetClientCertificate: func(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
					return clientCert, nil
				},
				RootCAs:      rootCAs,
				KeyLogWriter: ssllog,
			},
		},
	}
}
