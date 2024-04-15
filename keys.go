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
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"

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

// StatsForNerds captures metrics from various bifrost processes.
var StatsForNerds = metrics.NewSet()

// PublicKey is a wrapper around an ECDSA public key.
// It implements the Marshaler and Unmarshaler interfaces for binary, text, JSON, and DynamoDB.
// Keys are serialsed in PKIX, ASN.1 DER form.
type PublicKey struct {
	*ecdsa.PublicKey
}

func (p *PublicKey) Equal(other *PublicKey) bool {
	return p.PublicKey.Equal(other.PublicKey)
}

// UUID returns a unique identifier derived from the namespace and the client's public key.
func (p PublicKey) UUID(ns uuid.UUID) uuid.UUID {
	if p.PublicKey == nil {
		return uuid.Nil
	}
	return UUID(ns, &p)
}

// MarshalBinary marshals a public key to PKIX, ASN.1 DER form.
func (p PublicKey) MarshalBinary() ([]byte, error) {
	return x509.MarshalPKIXPublicKey(p.PublicKey)
}

// UnmarshalBinary unmarshals a public key from PKIX, ASN.1 DER form.
func (p *PublicKey) UnmarshalBinary(data []byte) error {
	pub, err := x509.ParsePKIXPublicKey(data)
	if err != nil {
		return err
	}
	pk, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("bifrost: unexpected key type %T", pub)
	}
	p.PublicKey = pk
	return nil
}

// MarshalText marshals the public key to a PEM encoded PKIX Public Key in ASN.1 DER form.
func (p PublicKey) MarshalText() ([]byte, error) {
	keyDer, err := p.MarshalBinary()
	if err != nil {
		return nil, err
	}
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: keyDer,
	}
	return pem.EncodeToMemory(block), nil
}

// UnmarshalText unmarshals the public key from a PEM encoded PKIX Public Key in ASN.1 DER form.
func (p *PublicKey) UnmarshalText(text []byte) error {
	block, _ := pem.Decode(text)
	if block == nil {
		return errors.New("bifrost: invalid PEM block")
	}
	return p.UnmarshalBinary(block.Bytes)
}

// MarshalJSON marshals the public key to a JSON string
// containing PEM encoded PKIX, ASN.1 DER form.
func (p PublicKey) MarshalJSON() ([]byte, error) {
	keyText, err := p.MarshalText()
	if err != nil {
		return nil, err
	}
	return json.Marshal(string(keyText))
}

// UnmarshalJSON unmarshals the public key as a JSON string
// containing PEM encoded PKIX Public Key, ASN.1 DER form.
func (p *PublicKey) UnmarshalJSON(data []byte) error {
	var keyString string
	if err := json.Unmarshal(data, &keyString); err != nil {
		return err
	}
	return p.UnmarshalText([]byte(keyString))
}

// MarshalDynamoDBAttributeValue marshals the public key to PKIX, ASN.1 DER form.
func (p PublicKey) MarshalDynamoDBAttributeValue() (types.AttributeValue, error) {
	keyDer, err := p.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return attributevalue.Marshal(keyDer)
}

// UnmarshalDynamoDBAttributeValue unmarshals the public key from PKIX, ASN.1 DER form.
func (p *PublicKey) UnmarshalDynamoDBAttributeValue(av types.AttributeValue) error {
	var keyDer []byte
	if err := attributevalue.Unmarshal(av, &keyDer); err != nil {
		return err
	}
	return p.UnmarshalBinary(keyDer)
}

// PrivateKey is a wrapper around an ECDSA private key.
// PrivateKey implements the Marshaler and Unmarshaler interfaces for binary, text, JSON, and DynamoDB.
// Keys are generated using the P-256 elliptic curve.
// Keys are serialised in PKCS #8, ASN.1 DER form.
type PrivateKey struct {
	*ecdsa.PrivateKey
}

// NewPrivateKey generates a new bifrost private key.
func NewPrivateKey() (*PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return &PrivateKey{
		PrivateKey: key,
	}, err
}

// PublicKey returns the public key corresponding to p.
func (p PrivateKey) PublicKey() *PublicKey {
	return &PublicKey{&p.PrivateKey.PublicKey}
}

// MarshalBinary converts a private key to PKCS #8, ASN.1 DER form.
func (p PrivateKey) MarshalBinary() ([]byte, error) {
	return x509.MarshalPKCS8PrivateKey(p.PrivateKey)
}

// UnmarshalBinary parses an unencrypted private key in PKCS #8, ASN.1 DER form.
func (p *PrivateKey) UnmarshalBinary(data []byte) error {
	priv, err := x509.ParsePKCS8PrivateKey(data)
	if err != nil {
		return err
	}
	k, ok := priv.(*ecdsa.PrivateKey)
	if !ok {
		return fmt.Errorf("bifrost: unexpected key type %T", priv)
	}
	p.PrivateKey = k
	return nil
}

// MarshalText marshals the key to a PEM encoded PKCS #8, ASN.1 DER form.
func (p PrivateKey) MarshalText() ([]byte, error) {
	keyDer, err := p.MarshalBinary()
	if err != nil {
		return nil, err
	}
	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyDer,
	}
	return pem.EncodeToMemory(block), nil
}

// UnmarshalText unmarshals the private key from PEM encoded PKCS #8, ASN.1 DER form.
// Unmarshal also supports EC PRIVATE KEY PEM blocks for backward compatibility.
func (p *PrivateKey) UnmarshalText(text []byte) error {
	block, _ := pem.Decode(text)
	if block == nil {
		return errors.New("bifrost: invalid PEM block")
	}
	switch block.Type {
	case "PRIVATE KEY":
		return p.UnmarshalBinary(block.Bytes)
	case "EC PRIVATE KEY":
		pk, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return err
		}
		p.PrivateKey = pk
		return nil
	default:
		return fmt.Errorf("bifrost: unsupported PEM block type %q", block.Type)
	}
}

// MarshalJSON marshals the key to a JSON string containing PEM encoded PKCS #8, ASN.1 DER form.
func (p PrivateKey) MarshalJSON() ([]byte, error) {
	keyText, err := p.MarshalText()
	if err != nil {
		return nil, err
	}
	return json.Marshal(string(keyText))
}

// UnmarshalJSON unmarshals the private key from PEM encoded PKCS #8, ASN.1 DER form.
func (p *PrivateKey) UnmarshalJSON(data []byte) error {
	var keyString string
	if err := json.Unmarshal(data, &keyString); err != nil {
		return err
	}
	return p.UnmarshalText([]byte(keyString))
}

// MarshalDynamoDBAttributeValue marshals the private key to PKCS #8, ASN.1 DER form.
func (p PrivateKey) MarshalDynamoDBAttributeValue() (types.AttributeValue, error) {
	keyDer, err := p.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return attributevalue.Marshal(keyDer)
}

// UnmarshalDynamoDBAttributeValue unmarshals the private key from PKCS #8, ASN.1 DER form.
func (p *PrivateKey) UnmarshalDynamoDBAttributeValue(av types.AttributeValue) error {
	var keyDer []byte
	if err := attributevalue.Unmarshal(av, &keyDer); err != nil {
		return err
	}
	return p.UnmarshalBinary(keyDer)
}

// UUID returns the bifrost identifier for p in the given namespace.
func (p PrivateKey) UUID(ns uuid.UUID) uuid.UUID {
	if p.PrivateKey == nil {
		return uuid.Nil
	}
	return UUID(ns, p.PublicKey())
}

// UUID returns a unique identifier derived from the namespace and the client's public key identity.
// The UUID is generated by SHA-1 hashing the namesapce UUID
// with the big endian bytes of the X and Y curve points from the public key.
func UUID(ns uuid.UUID, pubkey *PublicKey) uuid.UUID {
	if ns == uuid.Nil {
		return uuid.Nil
	}
	// X and Y are guaranteed to by 256 bits (32 bytes) each for elliptic curve P256 keys.
	var buf [64]byte
	pubkey.X.FillBytes(buf[:32])
	pubkey.Y.FillBytes(buf[32:])
	return uuid.NewSHA1(ns, buf[:])
}
