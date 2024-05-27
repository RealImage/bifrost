package tinyca

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math"
	"math/big"

	"github.com/RealImage/bifrost"
	"github.com/google/uuid"
)

// Templater returns a new x509.Certificate template for a CSR.
// The template will be used to issue a client certificate.
// If the function returns nil, the default template TLSClientCertTemplate will be used.
// Consult the x509 package for the full list of fields that can be set.
// tinyca will overwrite the following template fields:
//   - NotBefore
//   - NotAfter
//   - SignatureAlgorithm
//   - Issuer
//   - Subject.Organization
//   - Subject.CommonName
//   - BasicConstraintsValid
//
// If SerialNumber is nil, a random value will be generated.
type Templater func(csr *bifrost.CertificateRequest) *x509.Certificate

// TLSClientCertTemplate returns a new x509.Certificate template for a client certificate.
func TLSClientCertTemplate() *x509.Certificate {
	return &x509.Certificate{
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
}

// CACertTemplate returns a new x509.Certificate template for a CA certificate.
func CACertTemplate(ns, id uuid.UUID) (*x509.Certificate, error) {
	serialNumber, err := rand.Int(rand.Reader, big.NewInt(int64(math.MaxInt64)))
	if err != nil {
		return nil, fmt.Errorf("bifrost: unexpected error generating certificate serial: %w", err)
	}
	return &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{ns.String()},
			CommonName:   id.String(),
		},
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}, nil
}
