package bifrost

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
)

type singleHostRoundTripper struct {
	apiurl    *url.URL
	transport http.RoundTripper
}

func (s singleHostRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	r.URL.Scheme = s.apiurl.Scheme
	r.URL.Host = s.apiurl.Host
	path, err := url.JoinPath(s.apiurl.Path, r.URL.Path)
	if err != nil {
		return nil, fmt.Errorf("error joining request path with apiurl path: %w", err)
	}
	r.URL.Path = path
	return s.transport.RoundTrip(r)
}

// HTTPClient returns a HTTP client set up for mTLS with the provided api URL.
// The returned client will only send requests to the api URL host.
// The request path will be joined with the api URL path, if any.
// The client will use the provided TLS client certificate to identify itself.
func HTTPClient(apiUrl string, clientCert *tls.Certificate) (*http.Client, error) {
	u, err := url.Parse(apiUrl)
	if err != nil {
		return nil, err
	}
	return &http.Client{
		Transport: &singleHostRoundTripper{
			apiurl: u,
			transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					Certificates: []tls.Certificate{*clientCert},
				},
			},
		},
	}, nil
}
