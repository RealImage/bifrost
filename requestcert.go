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

	"github.com/VictoriaMetrics/metrics"
	"github.com/google/uuid"
)

// CertificateRequestTemplate returns a bifrost certificate request template for a namespace and public key.
func CertificateRequestTemplate(ns uuid.UUID, key *PublicKey) *x509.CertificateRequest {
	return &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   key.UUID(ns).String(),
			Organization: []string{ns.String()},
		},
		SignatureAlgorithm: SignatureAlgorithm,
	}
}

// RequestCertificate sends a certificate request over HTTP to url and returns the signed certificate.
func RequestCertificate(
	ctx context.Context,
	caUrl string,
	namespace uuid.UUID,
	key *PrivateKey,
) (*Certificate, error) {
	template := CertificateRequestTemplate(namespace, key.PublicKey())
	csr, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		return nil, fmt.Errorf("bifrost: error creating certificate request: %w", err)
	}

	resp, err := http.Post(caUrl+"/issue", "application/octet-stream", bytes.NewReader(csr))
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

	metrics.GetOrCreateCounter(
		fmt.Sprintf(`bifrost_certificate_requests_total{namespace="%s"}`, namespace),
	).Inc()

	return cert, nil
}
