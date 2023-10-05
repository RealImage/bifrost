package bifrost

import (
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"

	"github.com/google/uuid"
)

// Certificate is a bifrost certificate.
// It embeds the x509 certificate and adds the bifrost ID, namespace, and public key.
type Certificate struct {
	*x509.Certificate
	ID        uuid.UUID
	Namespace uuid.UUID
	PublicKey *ecdsa.PublicKey
}

// ParseCertificate parses a DER encoded certificate and validates it.
// On success, it returns the bifrost certificate.
func ParseCertificate(der []byte) (*Certificate, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	c := &Certificate{
		Certificate: cert,
	}
	if err := c.Verify(); err != nil {
		return nil, err
	}
	return c, nil
}

// Verify validates a bifrost certificate. It checks for the correct signature algorithm,
// identity namespace, and identity. On success, it sets the ID, Namespace, and PublicKey fields.
func (c *Certificate) Verify() error {
	// Check for bifrost signature algorithm
	if c.SignatureAlgorithm != SignatureAlgorithm {
		return fmt.Errorf(
			"%w: unsupported signature algorithm '%s'",
			ErrCertificateRequestFormat,
			c.SignatureAlgorithm,
		)
	}

	// Parse identity namespace
	if len(c.Subject.Organization) != 1 {
		return fmt.Errorf("%w: missing identity namespace", ErrCertificateFormat)
	}
	rawNS := c.Subject.Organization[0]
	ns, err := uuid.Parse(rawNS)
	if err != nil {
		return fmt.Errorf("%w: invalid identity namespace %s: %w", ErrCertificateFormat, rawNS, err)
	}
	if ns == uuid.Nil {
		return fmt.Errorf("%w: nil identity namespace", ErrCertificateFormat)
	}

	pubkey, ok := c.Certificate.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf(
			"%w: invalid public key type: '%T'",
			ErrCertificateFormat,
			c.Certificate.PublicKey,
		)
	}

	// Check if calculated UUID matches the UUID in the certificate
	id := UUID(ns, pubkey)
	cid, err := uuid.Parse(c.Subject.CommonName)
	if err != nil {
		return fmt.Errorf(
			"%w: invalid subj CN '%s', %v",
			ErrCertificateFormat,
			c.Subject.CommonName,
			err,
		)
	}
	if cid != id {
		return fmt.Errorf("%w: incorrect identity", ErrCertificateFormat)
	}

	c.ID = id
	c.Namespace = ns
	c.PublicKey = pubkey

	return nil
}

// ParseCertificateRequest parses a DER encoded certificate request and validates it.
// On success, it returns the bifrost namespace, certificate request, and certificate public key.
func ParseCertificateRequest(
	der []byte,
) (uuid.UUID, *x509.CertificateRequest, *ecdsa.PublicKey, error) {
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return uuid.Nil, nil, nil, err
	}
	ns, key, err := ValidateCertificateRequest(csr)
	if err != nil {
		return uuid.Nil, nil, nil, err
	}
	return ns, csr, key, nil
}

// ValidateCertificateRequest validates a bifrost certificate request.
// On success, it returns the bifrost namespace and certificate public key.
func ValidateCertificateRequest(csr *x509.CertificateRequest) (uuid.UUID, *ecdsa.PublicKey, error) {
	// Check for bifrost signature algorithm
	if csr.SignatureAlgorithm != SignatureAlgorithm {
		return uuid.Nil, nil, fmt.Errorf(
			"%w: unsupported signature algorithm '%s'",
			ErrCertificateRequestFormat,
			csr.SignatureAlgorithm,
		)
	}

	// Parse identity namespace
	if len(csr.Subject.Organization) != 1 {
		return uuid.Nil, nil, fmt.Errorf(
			"%w: missing identity namespace",
			ErrCertificateRequestFormat,
		)
	}
	rawNS := csr.Subject.Organization[0]
	ns, err := uuid.Parse(rawNS)
	if err != nil {
		return uuid.Nil, nil, fmt.Errorf(
			"%w: invalid identity namespace %s: %w",
			ErrCertificateRequestFormat,
			rawNS,
			err,
		)
	}

	pubkey, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return uuid.Nil, nil, fmt.Errorf(
			"%w: invalid public key type: '%T'",
			ErrCertificateRequestFormat,
			csr.PublicKey,
		)
	}

	// Check if calculated UUID matches the UUID in the certificate
	id := UUID(ns, pubkey)
	cid, err := uuid.Parse(csr.Subject.CommonName)
	if err != nil {
		return uuid.Nil, nil, fmt.Errorf("%w: invalid identity '%s', %v",
			ErrCertificateRequestFormat, csr.Subject.CommonName, err)
	}
	if cid != id {
		return uuid.Nil, nil, fmt.Errorf("%w: incorrect identity", ErrCertificateRequestFormat)
	}

	return ns, pubkey, nil
}
