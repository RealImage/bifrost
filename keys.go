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
// It implements the Marshaler and Unmarshaler interfaces for JSON and DynamoDB.
type PublicKey struct {
	*ecdsa.PublicKey
}

// MarshalPKIXPublicKey marshals a public key to PKIX, ASN.1 DER form.
func MarshalPKIXPublicKey(p *PublicKey) ([]byte, error) {
	return x509.MarshalPKIXPublicKey(p.PublicKey)
}

// ParsePKIXPublicKey parses a public key in PKIX, ASN.1 DER form.
func ParsePKIXPublicKey(asn1Data []byte) (*PublicKey, error) {
	pub, err := x509.ParsePKIXPublicKey(asn1Data)
	if err != nil {
		return nil, err
	}
	return &PublicKey{
		PublicKey: pub.(*ecdsa.PublicKey),
	}, nil
}

// UUID returns a unique identifier derived from the namespace and the client's public key.
func (p PublicKey) UUID(ns uuid.UUID) uuid.UUID {
	if p.PublicKey == nil {
		return uuid.Nil
	}
	return UUID(ns, &p)
}

// MarshalJSON marshals the public key to PEM encoded PKIX, ASN.1 DER form.
func (p PublicKey) MarshalJSON() ([]byte, error) {
	keyDer, err := MarshalPKIXPublicKey(&p)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: keyDer,
	}), nil
}

// UnmarshalJSON unmarshals the public key from PEM encoded PKIX, ASN.1 DER form.
func (p *PublicKey) UnmarshalJSON(data []byte) error {
	block, _ := pem.Decode(data)
	if block == nil {
		return errors.New("bifrost: invalid PEM block")
	}
	pkey, err := ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}
	*p = *pkey
	return nil
}

// MarshalDynamoDBAttributeValue marshals the public key to PKIX, ASN.1 DER form.
func (p PublicKey) MarshalDynamoDBAttributeValue() (types.AttributeValue, error) {
	keyDer, err := MarshalPKIXPublicKey(&p)
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
	pub, err := ParsePKIXPublicKey(keyDer)
	if err != nil {
		return err
	}
	*p = *pub
	return nil
}

// PrivateKey is a wrapper around an ECDSA private key.
// PrivateKey implements the Marshaler and Unmarshaler interfaces for JSON and DynamoDB.
// By default, PrivateKey's MarshalJSON method marshals the corresponding public key.
// This is equivalent to calling the PublicKey method and marshaling the result.
// Use WithJSONMarshalPrivateKey to marshal the private key instead.
type PrivateKey struct {
	*ecdsa.PrivateKey

	jsonMarshalPrivateKey bool
}

// MarshalECPrivateKey converts an EC Private Key to SEC 1, ASN.1 DER form.
func MarshalECPrivateKey(p *PrivateKey) ([]byte, error) {
	return x509.MarshalECPrivateKey(p.PrivateKey)
}

// ParseECPrivateKey parses an EC Private Key in SEC 1, ASN.1 DER form.
func ParseECPrivateKey(asn1Data []byte) (*PrivateKey, error) {
	priv, err := x509.ParseECPrivateKey(asn1Data)
	if err != nil {
		return nil, err
	}
	return &PrivateKey{
		PrivateKey: priv,
	}, nil
}

// MarshalPKCS8PrivateKey converts a private key to PKCS #8, ASN.1 DER form.
func MarshalPKCS8PrivateKey(p *PrivateKey) ([]byte, error) {
	return x509.MarshalPKCS8PrivateKey(p.PrivateKey)
}

// ParsePKCS8PrivateKey parses an unencrypted private key in PKCS #8, ASN.1 DER form.
func ParsePKCS8PrivateKey(asn1Data []byte) (*PrivateKey, error) {
	priv, err := x509.ParsePKCS8PrivateKey(asn1Data)
	if err != nil {
		return nil, err
	}
	k, ok := priv.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("bifrost: unexpected key type %T", priv)
	}
	return &PrivateKey{
		PrivateKey: k,
	}, nil
}

// NewPrivateKey generates a new bifrost private key.
func NewPrivateKey() (*PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return &PrivateKey{
		PrivateKey: key,
	}, err
}

// WithJSONMarshalPrivateKey configures the private key to be marshaled as a JSON object.
func (p *PrivateKey) WithJSONMarshalPrivateKey() *PrivateKey {
	p.jsonMarshalPrivateKey = true
	return p
}

// PublicKey returns the public key corresponding to p.
func (p PrivateKey) PublicKey() *PublicKey {
	return &PublicKey{&p.PrivateKey.PublicKey}
}

// MarshalJSON marshals the private key to PEM encoded PKCS #8, ASN.1 DER form.
func (p PrivateKey) MarshalJSON() ([]byte, error) {
	if !p.jsonMarshalPrivateKey {
		return p.PublicKey().MarshalJSON()
	}
	keyDer, err := MarshalECPrivateKey(&p)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyDer,
	}), nil
}

// UnmarshalJSON unmarshals the private key from PEM encoded PKCS #8, ASN.1 DER form.
func (p *PrivateKey) UnmarshalJSON(data []byte) error {
	block, _ := pem.Decode(data)
	if block == nil {
		return errors.New("bifrost: invalid PEM block")
	}
	priv, err := ParseECPrivateKey(block.Bytes)
	if err != nil {
		return err
	}
	*p = *priv
	return nil
}

// MarshalDynamoDBAttributeValue marshals the private key to PKCS #8, ASN.1 DER form.
func (p PrivateKey) MarshalDynamoDBAttributeValue() (types.AttributeValue, error) {
	keyDer, err := MarshalECPrivateKey(&p)
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
	priv, err := ParseECPrivateKey(keyDer)
	if err != nil {
		return err
	}
	*p = *priv
	return nil
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
