// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Bifrost is an mTLS authentication toolkit.
package bifrost

import (
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

// Signature and Public Key Algorithms
const (
	SignatureAlgorithm = x509.ECDSAWithSHA256
	PublicKeyAlgorithm = x509.ECDSA
)

// Namespace is the default UUID Namespace for Bifrost identities.
var Namespace = uuid.MustParse("1512daa4-ddc1-41d1-8673-3fd19d2f338d")

// Errors.
var (
	ErrInvalidPublicKey     = errors.New("invalid public key")
	ErrUnsupportedAlgorithm = errors.New("unsupported algorithm")
	ErrWrongNamespace       = errors.New("wrong namespace")
)

// UUID returns a unique identifier derived from the namespace and the client's public key identity.
// The UUID is generated by SHA-1 hashing the namesapce UUID
// with the big endian bytes of the X and Y curve points from the public key.
func UUID(ns uuid.UUID, pubkey *ecdsa.PublicKey) uuid.UUID {
	// X and Y are guaranteed to by 256 bits (32 bytes) for elliptic curve P256 keys
	var buf [64]byte
	pubkey.X.FillBytes(buf[:32])
	pubkey.Y.FillBytes(buf[32:])
	return uuid.NewSHA1(ns, buf[:])
}

// ParseCertificate returns the UUID and certificate from an ASN.1 DER encoded certificate.
func ParseCertificate(der []byte) (uuid.UUID, *x509.Certificate, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return uuid.UUID{}, nil, err
	}
	pubkey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return uuid.UUID{}, nil, fmt.Errorf(
			"invalid public key: %T, %w",
			cert.PublicKey,
			ErrInvalidPublicKey,
		)
	}
	if cert.SignatureAlgorithm != SignatureAlgorithm {
		return uuid.UUID{}, nil, fmt.Errorf(
			"unsupported signature algorithm: %s, %w",
			cert.SignatureAlgorithm,
			ErrUnsupportedAlgorithm,
		)
	}
	id := UUID(Namespace, pubkey)
	cnid, err := uuid.Parse(cert.Subject.CommonName)
	if err != nil {
		return uuid.UUID{}, nil, fmt.Errorf("invalid common name: %s", cert.Subject.CommonName)
	}
	if cnid != id {
		return uuid.UUID{}, nil, ErrWrongNamespace
	}
	return id, cert, nil
}
