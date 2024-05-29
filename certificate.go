package bifrost

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

// Errors
var (
	ErrCertificateInvalid        = errors.New("bifrost: certificate invalid")
	ErrNamespaceMismatch         = errors.New("bifrost: namespace mismatch")
	ErrCertificateRequestDenied  = errors.New("bifrost: certificate request denied")
	ErrCertificateRequestInvalid = errors.New("bifrost: certificate request invalid")
)

// Certificate is a bifrost certificate.
// It embeds the x509 certificate and adds the bifrost ID, namespace, and public key.
type Certificate struct {
	*x509.Certificate

	ID        uuid.UUID
	Namespace uuid.UUID
	PublicKey *PublicKey
}

func (c Certificate) IsCA() bool {
	return c.Certificate.BasicConstraintsValid &&
		c.Certificate.IsCA &&
		c.Certificate.KeyUsage&x509.KeyUsageCertSign != 0
}

// ParseCertificate parses a DER encoded certificate and validates it.
// On success, it returns the bifrost certificate.
func ParseCertificate(asn1Data []byte) (*Certificate, error) {
	cert, err := x509.ParseCertificate(asn1Data)
	if err != nil {
		return nil, err
	}
	return NewCertificate(cert)
}

// NewCertificate creates a bifrost certificate from an x509 certificate.
// It checks for the correct signature algorithm, identity namespace, and identity.
// On success, it sets the ID, Namespace, and PublicKey fields.
func NewCertificate(cert *x509.Certificate) (*Certificate, error) {
	if cert.IsCA {
		if !cert.BasicConstraintsValid {
			return nil, fmt.Errorf("%w, basic constraints not valid", ErrCertificateInvalid)
		}

		if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
			return nil, fmt.Errorf("%w, certificate is a CA but cannot sign", ErrCertificateInvalid)
		}
	}

	// Check for bifrost signature algorithm
	if cert.SignatureAlgorithm != SignatureAlgorithm {
		return nil, fmt.Errorf(
			"%w, unsupported signature algorithm '%s'",
			ErrCertificateRequestInvalid,
			cert.SignatureAlgorithm,
		)
	}

	// Parse identity namespace
	if len(cert.Subject.Organization) != 1 {
		return nil, fmt.Errorf("%w, missing identity namespace", ErrCertificateInvalid)
	}
	rawNS := cert.Subject.Organization[0]
	ns, err := uuid.Parse(rawNS)
	if err != nil {
		return nil, fmt.Errorf(
			"%w, invalid identity namespace %s: %w",
			ErrCertificateInvalid,
			rawNS,
			err,
		)
	}
	if ns == uuid.Nil {
		return nil, fmt.Errorf("%w, nil identity namespace", ErrCertificateInvalid)
	}

	pubkey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf(
			"%w, invalid public key type: '%T'",
			ErrCertificateInvalid,
			cert.PublicKey,
		)
	}

	pk := &PublicKey{
		PublicKey: pubkey,
	}

	// Check if calculated UUID matches the UUID in the certificate
	id := pk.UUID(ns)

	cid, err := uuid.Parse(cert.Subject.CommonName)
	if err != nil {
		return nil, fmt.Errorf(
			"%w, invalid subj CN '%s', %s",
			ErrCertificateInvalid,
			cert.Subject.CommonName,
			err.Error(),
		)
	}
	if cid != id {
		return nil, fmt.Errorf("%w, incorrect identity", ErrCertificateInvalid)
	}

	bfCert := &Certificate{
		Certificate: cert,
		ID:          id,
		Namespace:   ns,
		PublicKey:   pk,
	}

	return bfCert, nil
}

// IssuedTo returns true if the certificate was issued to the given public key.
func (c *Certificate) IssuedTo(key *PublicKey) bool {
	return c.PublicKey.Equal(key)
}

// ToTLSCertificate returns a tls.Certificate from a bifrost certificate and private key.
func (c Certificate) ToTLSCertificate(key PrivateKey) (*tls.Certificate, error) {
	if key.PrivateKey == nil {
		return nil, errors.New("private key is nil")
	}
	if !c.IssuedTo(key.PublicKey()) {
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

// CertificateRequest is a bifrost certificate request.
// It embeds the x509 certificate request and adds the bifrost ID, namespace, and public key.
type CertificateRequest struct {
	*x509.CertificateRequest

	ID        uuid.UUID
	Namespace uuid.UUID
	PublicKey *PublicKey
}

// ParseCertificateRequest parses a DER encoded certificate request and validates it.
// On success, it returns the bifrost namespace, certificate request, and certificate public key.
func ParseCertificateRequest(asn1Data []byte) (*CertificateRequest, error) {
	csr, err := x509.ParseCertificateRequest(asn1Data)
	if err != nil {
		return nil, fmt.Errorf("%w, %s", ErrCertificateRequestInvalid, err.Error())
	}
	return NewCertificateRequest(csr)
}

// NewCertificateRequest creates a bifrost certificate request from an x509 certificate request.
// It checks for the correct signature algorithm, identity namespace, and identity.
// On success, it sets the ID, Namespace, and PublicKey fields.
func NewCertificateRequest(cert *x509.CertificateRequest) (*CertificateRequest, error) {
	// Check for bifrost signature algorithm
	if cert.SignatureAlgorithm != SignatureAlgorithm {
		return nil, fmt.Errorf(
			"%w, unsupported signature algorithm '%s'",
			ErrCertificateRequestInvalid,
			cert.SignatureAlgorithm,
		)
	}

	// Parse identity namespace
	if len(cert.Subject.Organization) != 1 {
		return nil, fmt.Errorf(
			"%w, missing identity namespace",
			ErrCertificateRequestInvalid,
		)
	}
	rawNS := cert.Subject.Organization[0]
	ns, err := uuid.Parse(rawNS)
	if err != nil {
		return nil, fmt.Errorf(
			"%w, invalid identity namespace %s: %w",
			ErrCertificateRequestInvalid,
			rawNS,
			err,
		)
	}

	pubkey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf(
			"%w, invalid public key type: '%T'",
			ErrCertificateRequestInvalid,
			cert.PublicKey,
		)
	}

	pk := &PublicKey{
		PublicKey: pubkey,
	}

	// Check if calculated UUID matches the UUID in the certificate
	id := pk.UUID(ns)
	cid, err := uuid.Parse(cert.Subject.CommonName)
	if err != nil {
		return nil, fmt.Errorf("%w, invalid identity '%s', %s",
			ErrCertificateRequestInvalid, cert.Subject.CommonName, err.Error())
	}
	if cid != id {
		return nil, fmt.Errorf("%w, incorrect identity", ErrCertificateRequestInvalid)
	}

	bfReq := &CertificateRequest{
		CertificateRequest: cert,
		ID:                 id,
		Namespace:          ns,
		PublicKey:          pk,
	}

	return bfReq, nil
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
