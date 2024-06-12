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
// The returned error wraps ErrCertificateRequestInvalid or ErrCertificateRequestDenied
// if the request is invalid or denied.
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

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		caUrl+"/issue",
		bytes.NewReader(csr),
	)
	if err != nil {
		return nil, fmt.Errorf("bifrost: error creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("bifrost: error sending request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("bifrost: unexpected error reading response body: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusBadRequest:
		return nil, fmt.Errorf("%w, response: %s", ErrRequestInvalid, body)
	case http.StatusForbidden:
		return nil, fmt.Errorf("%w, response: %s", ErrRequestDenied, body)
	case http.StatusServiceUnavailable:
		return nil, fmt.Errorf("%w, response: %s", ErrRequestAborted, body)
	default:
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

// GetNamespace returns the namespace from the CA at url.
func GetNamespace(ctx context.Context, caUrl string) (uuid.UUID, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, caUrl+"/namespace", nil)
	if err != nil {
		return uuid.Nil, fmt.Errorf("bifrost: error creating request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return uuid.Nil, fmt.Errorf("bifrost: error sending request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return uuid.Nil, fmt.Errorf("bifrost: unexpected response status: %s", resp.Status)
	}

	var nss string
	if _, err := fmt.Fscan(resp.Body, &nss); err != nil {
		return uuid.Nil, fmt.Errorf("bifrost: error reading response body: %w", err)
	}

	ns, err := uuid.Parse(nss)
	if err != nil {
		return uuid.Nil, fmt.Errorf("bifrost: error parsing namespace: %w", err)
	}

	return ns, nil
}
