package bifrost

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
)

type singleHostRoundTripper struct {
	apiUrl    *url.URL
	transport http.RoundTripper
}

func (s singleHostRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	if s.apiUrl != nil {
		r.URL.Host = s.apiUrl.Host
		var err error
		if r.URL.Path, err = url.JoinPath(s.apiUrl.Path, r.URL.Path); err != nil {
			return nil, fmt.Errorf("error joining request path with apiurl path: %w", err)
		}
	}
	return s.transport.RoundTrip(r)
}

// HTTPClient returns a http.Client configured for mTLS with apiUrl.
// If clientCert is not nil, it will be used for client authentication.
// If rootCAs is not nil, it will be used to verify the server certificate.
func HTTPClient(apiUrl string, clientCert *tls.Certificate, rootCAs *x509.CertPool) (*http.Client, error) {
	rt := &singleHostRoundTripper{
		transport: http.DefaultTransport,
	}
	if apiUrl != "" {
		u, err := url.Parse(apiUrl)
		if err != nil {
			return nil, err
		}
		rt.apiUrl = u
	}
	if clientCert != nil {
		rt.transport = &http.Transport{
			Proxy:             http.ProxyFromEnvironment,
			ForceAttemptHTTP2: true,
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{*clientCert},
				RootCAs:      rootCAs,
			},
		}
	}
	return &http.Client{Transport: rt}, nil
}
