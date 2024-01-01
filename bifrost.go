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
	"encoding/pem"
	"errors"

	"github.com/VictoriaMetrics/metrics"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
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

// PublicKey is a wrapper around an ECDSA public key.
// It implements the Marshaler and Unmarshaler interfaces for JSON and DynamoDB.
type PublicKey struct {
	*ecdsa.PublicKey
}

// UUID returns a unique identifier derived from the namespace and the client's public key.
func (p PublicKey) UUID(ns uuid.UUID) uuid.UUID {
	return UUID(ns, p.PublicKey)
}

func (p PublicKey) MarshalJSON() ([]byte, error) {
	keyDer, err := x509.MarshalPKIXPublicKey(p.PublicKey)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: keyDer,
	}), nil
}

func (p *PublicKey) UnmarshalJSON(data []byte) error {
	block, _ := pem.Decode(data)
	if block == nil {
		return errors.New("bifrost: invalid PEM block")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}
	p.PublicKey = pub.(*ecdsa.PublicKey)
	return nil
}

func (p PublicKey) MarshalDynamoDBAttributeValue() (types.AttributeValue, error) {
	keyDer, err := x509.MarshalPKIXPublicKey(p.PublicKey)
	if err != nil {
		return nil, err
	}
	return attributevalue.Marshal(keyDer)
}

func (p *PublicKey) UnmarshalDynamoDBAttributeValue(av types.AttributeValue) error {
	var keyDer []byte
	if err := attributevalue.Unmarshal(av, &keyDer); err != nil {
		return err
	}
	pub, err := x509.ParsePKIXPublicKey(keyDer)
	if err != nil {
		return err
	}
	p.PublicKey = pub.(*ecdsa.PublicKey)
	return nil
}

// NewPrivateKey generates a new private key for use with bifrost.
func NewPrivateKey() (*ecdsa.PrivateKey, error) {
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
