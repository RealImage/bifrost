package bifrost

import (
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

// Identity represents a unique identity in the system.
type Identity struct {
	Namespace uuid.UUID
	PublicKey *PublicKey
}

func (i Identity) UUID() uuid.UUID {
	return i.PublicKey.UUID(i.Namespace)
}

func ParseIdentity(data []byte) (*Identity, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM data found")
	}

	// Parse the key or certificate.
	switch block.Type {
	case "PRIVATE KEY":
		privkey, err := ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return &Identity{
			PublicKey: privkey.PublicKey(),
		}, nil
	case "EC PRIVATE KEY":
		privkey, err := ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return &Identity{
			PublicKey: privkey.PublicKey(),
		}, nil
	case "PUBLIC KEY":
		pubkey, err := ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return &Identity{
			PublicKey: pubkey,
		}, nil
	case "CERTIFICATE":
		cert, err := ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		ns := cert.Namespace
		return &Identity{
			Namespace: ns,
			PublicKey: cert.PublicKey,
		}, nil
	case "CERTIFICATE REQUEST":
		csr, err := ParseCertificateRequest(block.Bytes)
		if err != nil {
			return nil, err
		}
		ns := csr.Namespace
		return &Identity{
			Namespace: ns,
			PublicKey: csr.PublicKey,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported PEM block type: %s", block.Type)
	}
}