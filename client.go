package bifrost

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"
)

// HTTPClient returns a http.Client set up for TLS Client Authentication (mTLS).
// The client will request a new certificate from the bifrost caUrl when needed.
// If roots is not nil, then only those Root CAs are used to authenticate server certs.
// If ssllog is not nil, the client will log TLS key material to it.
func HTTPClient(
	caUrl string,
	ns uuid.UUID,
	privkey *PrivateKey,
	roots *x509.CertPool,
	ssllog io.Writer,
) (*http.Client, error) {
	cr := &certRefresher{
		url:     caUrl,
		ns:      ns,
		privkey: privkey,
	}
	if _, err := cr.GetClientCertificate(nil); err != nil {
		return nil, err
	}
	tlsConfig := &tls.Config{
		GetClientCertificate: cr.GetClientCertificate,
		RootCAs:              roots,
		KeyLogWriter:         ssllog,
	}
	tlsTransport := http.DefaultTransport.(*http.Transport).Clone()
	tlsTransport.TLSClientConfig = tlsConfig
	return &http.Client{
		Transport: tlsTransport,
	}, nil
}

type certRefresher struct {
	url     string
	ns      uuid.UUID
	privkey *PrivateKey
	cert    *Certificate
}

func (cr *certRefresher) GetClientCertificate(
	info *tls.CertificateRequestInfo,
) (*tls.Certificate, error) {
	ctx := context.Background()
	if info != nil {
		ctx = info.Context()
	}
	// If the certificate is nil or is going to expire soon, request a new one.
	if cr.cert == nil || cr.cert.NotAfter.Before(time.Now().Add(-time.Minute*10)) {
		cert, err := RequestCertificate(ctx, cr.url, cr.ns, cr.privkey)
		if err != nil {
			return nil, err
		}
		cr.cert = cert
	}

	tlsCert := X509ToTLSCertificate(cr.cert.Certificate, cr.privkey.PrivateKey)

	if info != nil {
		if err := info.SupportsCertificate(tlsCert); err != nil {
			return nil, err
		}
	}

	return tlsCert, nil
}
