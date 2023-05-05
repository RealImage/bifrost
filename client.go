package bifrost

import (
	"crypto/tls"
	"net/http"
)

// HTTPClient returns a HTTP client that uses the provided certificate for
// mutual TLS authentication.
func HTTPClient(cert *tls.Certificate) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{*cert},
			},
		},
	}
}
