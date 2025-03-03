package bifrost

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"sync/atomic"
	"time"
)

// HTTPClient returns a http.Client set up for TLS Client Authentication (mTLS).
// The client will request a new certificate from the bifrost caUrl when needed.
// If roots is not nil, then only those Root CAs are used to authenticate server certs.
// If ssllog is not nil, the client will log TLS key material to it.
func HTTPClient(
	caUrl string,
	privkey *PrivateKey,
	roots *x509.CertPool,
	ssllog io.Writer,
) (*http.Client, error) {
	cr := &certRefresher{
		url:     caUrl,
		privkey: privkey,
	}
	if _, err := cr.getClientCertificate(nil); err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{
		GetClientCertificate: cr.getClientCertificate,
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
	privkey *PrivateKey
	cert    atomic.Pointer[Certificate]
}

func (cr *certRefresher) getClientCertificate(
	info *tls.CertificateRequestInfo,
) (*tls.Certificate, error) {
	ctx := context.Background()
	if info != nil {
		ctx = info.Context()
	}

	// If we don't have a certificate or it's about to expire, request a new one.
	if cert := cr.cert.Load(); cert == nil || time.Until(cert.NotAfter) < 10*time.Minute {
		Logger().DebugContext(ctx, "refreshing client certificate")

		cert, err := RequestCertificate(ctx, cr.url, cr.privkey)
		if err != nil {
			return nil, err
		}

		for {
			oldCert := cr.cert.Load()
			if cr.cert.CompareAndSwap(oldCert, cert) {
				break
			}
		}
		Logger().InfoContext(ctx, "got new client certificate",
			"namespace", cert.Namespace, "uuid", cert.ID)
	}

	tlsCert := X509ToTLSCertificate(cr.cert.Load().Certificate, cr.privkey.PrivateKey)

	if info != nil {
		if err := info.SupportsCertificate(tlsCert); err != nil {
			return nil, err
		}
	}

	return tlsCert, nil
}
