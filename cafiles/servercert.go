package cafiles

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net"
	"time"

	"github.com/RealImage/bifrost"
	"github.com/RealImage/bifrost/tinyca"
)

// CreateServerCertificate creates a TLS server certificate signed by the given CA.
// The certificate is valid for the given duration. If the duration is zero, the
// certificate is valid for one year.
func CreateServerCertificate(
	caCert *bifrost.Certificate,
	caKey *ecdsa.PrivateKey,
	validity time.Duration,
) (*bifrost.Certificate, *ecdsa.PrivateKey, error) {
	if validity == 0 {
		validity = time.Hour * 24 * 365
	}
	ca, err := tinyca.New(caCert, caKey, validity)
	if err != nil {
		return nil, nil, err
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("error generating server key: %w", err)
	}

	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   bifrost.UUID(caCert.Namespace, key.PublicKey).String(),
			Organization: []string{caCert.Namespace.String()},
		},
		SignatureAlgorithm: bifrost.SignatureAlgorithm,
		DNSNames:           []string{"localhost"},
		IPAddresses:        []net.IP{net.ParseIP("127.0.0.0")},
	}
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, key)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating certificate request: %w", err)
	}

	keyUsage := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	extKeyUsage := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}

	certBytes, err := ca.IssueCertificate(csrBytes, keyUsage, extKeyUsage)
	if err != nil {
		return nil, nil, fmt.Errorf("error issuing server certificate: %w", err)
	}

	cert, err := bifrost.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("error parsing server certificate: %w", err)
	}
	return cert, key, nil
}
