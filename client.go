package bifrost

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/url"
)

// Hosts is a map of hostnames to backend URLs.
type Hosts map[string]*url.URL

type mappedHostTransport struct {
	hosts     Hosts
	transport http.RoundTripper
}

func (t *mappedHostTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if u, ok := t.hosts[req.Host]; ok {
		req.URL.Scheme = u.Scheme
		req.URL.Host = u.Host
		path, err := url.JoinPath(u.Path, req.URL.Path)
		if err != nil {
			return nil, err
		}
		req.URL.Path = "/" + path
	}
	return t.transport.RoundTrip(req)
}

// HTTPClient returns a http.Client configured for mTLS with client authentication.
// The client will use the provided Hosts map to map hostnames to backend URLs.
// Client certificates are loaded from clientCert and rootCAs is used to
// validate the server certificate.
// If ssllog is not nil, the client will log TLS key material to it.
func HTTPClient(
	h Hosts,
	clientCert *tls.Certificate,
	rootCAs *x509.CertPool,
	ssllog io.Writer,
) *http.Client {
	return &http.Client{
		Transport: &mappedHostTransport{
			hosts: h,
			transport: &http.Transport{
				Proxy:             http.ProxyFromEnvironment,
				ForceAttemptHTTP2: true,
				TLSClientConfig: &tls.Config{
					Certificates: []tls.Certificate{*clientCert},
					RootCAs:      rootCAs,
					KeyLogWriter: ssllog,
				},
			},
		},
	}
}
