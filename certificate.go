package bifrost

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

// Certificate is a bifrost certificate.
// It embeds the x509 certificate and adds the bifrost ID, namespace, and public key.
type Certificate struct {
	*x509.Certificate
	Id        uuid.UUID
	Namespace uuid.UUID
	PublicKey *ecdsa.PublicKey
}

// ParseCertificate parses a DER encoded certificate and validates it.
// On success, it returns the bifrost certificate.
func ParseCertificate(asn1Data []byte) (*Certificate, error) {
	cert, err := x509.ParseCertificate(asn1Data)
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
			ErrCertificateRequestInvalid,
			c.SignatureAlgorithm,
		)
	}

	// Parse identity namespace
	if len(c.Subject.Organization) != 1 {
		return fmt.Errorf("%w: missing identity namespace", ErrCertificateInvalid)
	}
	rawNS := c.Subject.Organization[0]
	ns, err := uuid.Parse(rawNS)
	if err != nil {
		return fmt.Errorf(
			"%w: invalid identity namespace %s: %w",
			ErrCertificateInvalid,
			rawNS,
			err,
		)
	}
	if ns == uuid.Nil {
		return fmt.Errorf("%w: nil identity namespace", ErrCertificateInvalid)
	}

	pubkey, ok := c.Certificate.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf(
			"%w: invalid public key type: '%T'",
			ErrCertificateInvalid,
			c.Certificate.PublicKey,
		)
	}

	// Check if calculated UUID matches the UUID in the certificate
	id := UUID(ns, pubkey)
	cid, err := uuid.Parse(c.Subject.CommonName)
	if err != nil {
		return fmt.Errorf(
			"%w: invalid subj CN '%s', %s",
			ErrCertificateInvalid,
			c.Subject.CommonName,
			err.Error(),
		)
	}
	if cid != id {
		return fmt.Errorf("%w: incorrect identity", ErrCertificateInvalid)
	}

	c.Id = id
	c.Namespace = ns
	c.PublicKey = pubkey

	return nil
}

// ToTLSCertificate puts a bifrost certificate inside a tls.Certificate.
func (c Certificate) ToTLSCertificate(key *ecdsa.PrivateKey) (*tls.Certificate, error) {
	if c.PublicKey.X.Cmp(key.X) != 0 || c.PublicKey.Y.Cmp(key.Y) != 0 {
		return nil, errors.New("private key does not match certificate public key")
	}

	return &tls.Certificate{
		Certificate: [][]byte{
			c.Raw,
		},
		PrivateKey: key,
		Leaf:       c.Certificate,
	}, nil
}

type CertificateRequest struct {
	*x509.CertificateRequest
	Id        uuid.UUID
	Namespace uuid.UUID
	PublicKey *ecdsa.PublicKey
}

// ParseCertificateRequest parses a DER encoded certificate request and validates it.
// On success, it returns the bifrost namespace, certificate request, and certificate public key.
func ParseCertificateRequest(asn1Data []byte) (*CertificateRequest, error) {
	csr, err := x509.ParseCertificateRequest(asn1Data)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrCertificateRequestInvalid, err.Error())
	}
	c := &CertificateRequest{
		CertificateRequest: csr,
	}
	if err := c.Verify(); err != nil {
		return nil, err
	}
	return c, nil
}

// Verify validates a bifrost certificate request.
func (c *CertificateRequest) Verify() error {
	// Check for bifrost signature algorithm
	if c.SignatureAlgorithm != SignatureAlgorithm {
		return fmt.Errorf(
			"%w: unsupported signature algorithm '%s'",
			ErrCertificateRequestInvalid,
			c.SignatureAlgorithm,
		)
	}

	// Parse identity namespace
	if len(c.Subject.Organization) != 1 {
		return fmt.Errorf(
			"%w: missing identity namespace",
			ErrCertificateRequestInvalid,
		)
	}
	rawNS := c.Subject.Organization[0]
	ns, err := uuid.Parse(rawNS)
	if err != nil {
		return fmt.Errorf(
			"%w: invalid identity namespace %s: %w",
			ErrCertificateRequestInvalid,
			rawNS,
			err,
		)
	}

	pubkey, ok := c.CertificateRequest.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf(
			"%w: invalid public key type: '%T'",
			ErrCertificateRequestInvalid,
			c.PublicKey,
		)
	}

	// Check if calculated UUID matches the UUID in the certificate
	id := UUID(ns, pubkey)
	cid, err := uuid.Parse(c.Subject.CommonName)
	if err != nil {
		return fmt.Errorf("%w: invalid identity '%s', %s",
			ErrCertificateRequestInvalid, c.Subject.CommonName, err.Error())
	}
	if cid != id {
		return fmt.Errorf("%w: incorrect identity", ErrCertificateRequestInvalid)
	}

	c.Id = id
	c.Namespace = ns
	c.PublicKey = pubkey

	return nil
}

// X509ToTLSCertificate puts an x509.Certificate inside a tls.Certificate.
func X509ToTLSCertificate(cert *x509.Certificate, key *ecdsa.PrivateKey) *tls.Certificate {
	return &tls.Certificate{
		Certificate: [][]byte{
			cert.Raw,
		},
		PrivateKey: key,
		Leaf:       cert,
	}
}
