// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Bifrost is an mTLS authentication toolkit.
package bifrost

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"github.com/google/uuid"
)

// Signature and Public Key Algorithms
const (
	SignatureAlgorithm = x509.ECDSAWithSHA256
	PublicKeyAlgorithm = x509.ECDSA
)

// Errors.
var (
	ErrCertificateInvalid        = errors.New("certificate invalid")
	ErrCertificateRequestInvalid = errors.New("certificate request invalid")
	ErrIncorrectMismatch         = errors.New("namespace mismatch")
)

// NewIdentity generates a new ECDSA private key.
// The private key is also returned as a PEM encoded DER bytes in the second return value.
func NewIdentity() (*ecdsa.PrivateKey, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	keyDer, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	keyPem := pem.EncodeToMemory(&pem.Block{
		Type: "EC PRIVATE KEY", Headers: nil, Bytes: keyDer,
	})
	return key, keyPem, nil
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
