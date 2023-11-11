// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package bifrost

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
)

// HTTPClient returns a http.Client set up for TLS Client Authentication (mTLS).
// If roots is not nil, then only those Root CAs are used to authenticate server certs.
// If ssllog is not nil, the client will log TLS key material to it.
func HTTPClient(clientCert tls.Certificate, roots *x509.CertPool, ssllog io.Writer) *http.Client {
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      roots,
		KeyLogWriter: ssllog,
	}
	tlsTransport := http.DefaultTransport.(*http.Transport).Clone()
	tlsTransport.TLSClientConfig = tlsConfig
	return &http.Client{
		Transport: tlsTransport,
	}
}
