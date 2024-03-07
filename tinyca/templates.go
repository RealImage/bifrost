package tinyca

import (
	"crypto/x509"
	"crypto/x509/pkix"
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

func CACertTemplate(nb, na time.Time, ns, id uuid.UUID) *x509.Certificate {
	return &x509.Certificate{
		Subject: pkix.Name{
			Organization: []string{ns.String()},
			CommonName:   id.String(),
		},
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
}
