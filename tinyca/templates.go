package tinyca

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math"
	"math/big"
	"time"

	"github.com/google/uuid"
)

func TLSClientCertTemplate(nb, na time.Time) *x509.Certificate {
	return &x509.Certificate{
		NotBefore:             nb,
		NotAfter:              na,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
}

func CACertTemplate(nb, na time.Time, ns, id uuid.UUID) (*x509.Certificate, error) {
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
		NotBefore:             nb,
		NotAfter:              na,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}, nil
}
