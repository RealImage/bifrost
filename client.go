package bifrost

import (
	"crypto/tls"
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
		r.URL.Scheme = s.apiUrl.Scheme
		r.URL.Host = s.apiUrl.Host
		path, err := url.JoinPath(s.apiUrl.Path, r.URL.Path)
		if err != nil {
			return nil, fmt.Errorf("error joining request path with apiurl path: %w", err)
		}
		r.URL.Path = path
	}
	return s.transport.RoundTrip(r)
}

// HTTPClient returns a HTTP client set up for mTLS with the provided api URL.
// The returned client will only send requests to the api URL host.
// The request path will be joined with the api URL path, if any.
// The client will use the provided TLS client certificate to identify itself.
func HTTPClient(apiUrl string, clientCert *tls.Certificate) (*http.Client, error) {
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
			},
		}
	}
	return &http.Client{Transport: rt}, nil
}
