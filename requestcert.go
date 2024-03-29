package bifrost

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"net/http"
	"sync"

	"github.com/VictoriaMetrics/metrics"
	"github.com/google/uuid"
)

var nsMetricsMap = sync.Map{}

func getNsMetrics(namespace uuid.UUID) *metrics.Counter {
	m, ok := nsMetricsMap.Load(namespace)
	if !ok {
		m = metrics.NewCounter(
			fmt.Sprintf(`bifrost_certificate_requests_total{namespace="%s"}`, namespace),
		)
		nsMetricsMap.Store(namespace, m)
	}
	return m.(*metrics.Counter)
}

// Template returns a bifrost certificate template for the given namespace and public key.
func Template(ns uuid.UUID, key *PublicKey) *x509.CertificateRequest {
	return &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   key.UUID(ns).String(),
			Organization: []string{ns.String()},
		},
		SignatureAlgorithm: SignatureAlgorithm,
	}
}

// RequestCertificate sends a certificate request to url and returns the signed certificate.
func RequestCertificate(
	ctx context.Context,
	url string,
	ns uuid.UUID,
	key *PrivateKey,
) (*Certificate, error) {
	template := Template(ns, key.PublicKey())
	csr, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		return nil, fmt.Errorf("bifrost: error creating certificate request: %w", err)
	}

	resp, err := http.Post(url+"/issue", "application/octet-stream", bytes.NewReader(csr))
	if err != nil || resp == nil {
		return nil, fmt.Errorf("bifrost: error creating certificate request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("bifrost: unexpected error reading response body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(
			"bifrost: unexpected response status: %s, body: %s",
			resp.Status,
			body,
		)
	}

	cert, err := ParseCertificate(body)
	if err != nil {
		return nil, fmt.Errorf("bifrost: error parsing certificate: %w", err)
	}

	getNsMetrics(ns).Inc()

	return cert, nil
}
