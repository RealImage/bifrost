package bifrost

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"net/http"

	"github.com/hashicorp/go-retryablehttp"
)

// RequestCertificateKey sends a certificate request to url and returns the signed certificate
// along with the locally generated private key.
func RequestCertificateKey(ctx context.Context,
	url string, template *x509.CertificateRequest) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("error generating key %w", err)
	}
	crt, err := RequestCertificate(ctx, url, key, template)
	return crt, key, err
}

// RequestCertificate sends a certificate request to url and returns the signed certificate.
// If template is nil, a default template is used.
// The CommonName is the UUID of the public key by default.
func RequestCertificate(ctx context.Context, url string, privateKey *ecdsa.PrivateKey, template *x509.CertificateRequest) (*x509.Certificate, error) {
	if template == nil {
		// default template
		template = &x509.CertificateRequest{
			Subject: pkix.Name{
				CommonName: UUID(privateKey.PublicKey).String(),
			},
			SignatureAlgorithm: SignatureAlgorithm,
		}
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, template, privateKey)
	if err != nil {
		return nil, err
	}

	client := retryablehttp.NewClient()
	resp, err := client.Post(url, "application/octet-stream", csr)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected response status: %d %s", resp.StatusCode, resp.Status)
	}

	certDer, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(certDer)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

// Convert an x509.Certificate to a tls.Certificate
func X509ToTLSCertificate(crt *x509.Certificate, key *ecdsa.PrivateKey) *tls.Certificate {
	return &tls.Certificate{
		Certificate: [][]byte{
			crt.Raw,
		},
		PrivateKey: key,
		Leaf:       crt,
	}
}
