package bifrost

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"net/http"

	"github.com/hashicorp/go-retryablehttp"
)

// RequestSignature sends a CSR to url and returns a signed certificate
// parsed from the response.
// If template is nil, a default template is used.
// The CommonName is the UUID of the public key by default.
func RequestSignature(ctx context.Context, url string, privateKey ecdsa.PrivateKey, template *x509.CertificateRequest) (*tls.Certificate, error) {
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

	tlsCert := tls.Certificate{
		Certificate: [][]byte{
			cert.Raw,
		},
		PrivateKey: privateKey,
		Leaf:       cert,
	}

	return &tlsCert, nil
}
