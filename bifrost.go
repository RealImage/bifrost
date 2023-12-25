// Package bifrost provides simple Public Key Infrastructure (PKI) services.
//
// Bifrost identifies clients by their private keys.
// Keys are deterministically mapped to UUIDs by hashing them with the namespace UUID.
// The same key maps to different UUIDs in different namespaces.
// Clients can request certificates for their UUIDs.
// The certificates are signed by a root CA.
package bifrost

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"

	"github.com/VictoriaMetrics/metrics"
	"github.com/google/uuid"
)

// Signature and Public Key Algorithms
const (
	SignatureAlgorithm = x509.ECDSAWithSHA256
	PublicKeyAlgorithm = x509.ECDSA
)

// Errors.
var (
	ErrCertificateInvalid        = errors.New("bifrost: certificate invalid")
	ErrCertificateRequestInvalid = errors.New("bifrost: certificate request invalid")
	ErrIncorrectMismatch         = errors.New("bifrost: namespace mismatch")
)

// StatsForNerds captures metrics from various bifrost processes.
var StatsForNerds = metrics.NewSet()

// NewIdentity generates a new private key for use as a Bifrost identity.
func NewIdentity() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// UUID returns a unique identifier derived from the namespace and the client's public key identity.
// The UUID is generated by SHA-1 hashing the namesapce UUID
// with the big endian bytes of the X and Y curve points from the public key.
func UUID(ns uuid.UUID, pubkey *ecdsa.PublicKey) uuid.UUID {
	if ns == uuid.Nil || pubkey == nil {
		return uuid.Nil
	}
	// X and Y are guaranteed to by 256 bits (32 bytes) each for elliptic curve P256 keys.
	var buf [64]byte
	pubkey.X.FillBytes(buf[:32])
	pubkey.Y.FillBytes(buf[32:])
	return uuid.NewSHA1(ns, buf[:])
}
