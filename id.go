package bifrost

import (
	"crypto/ecdsa"

	"github.com/google/uuid"
)

// Namespace_Bifrost is the default UUID Namespace for Bifrost identities.
var Namespace_Bifrost = uuid.MustParse("1512daa4-ddc1-41d1-8673-3fd19d2f338d")

// UUID returns a unique identifier derived from the namespace and the client's public key identity.
// The UUID is generated by SHA-1 hashing the namesapce UUID
// with the big endian bytes of the X and Y curve points from the public key.
func UUID(namespace uuid.UUID, pubkey ecdsa.PublicKey) uuid.UUID {
	// X and Y are guaranteed to by 256 bits (32 bytes) for elliptic curve P256 keys
	var buf [64]byte
	pubkey.X.FillBytes(buf[:32])
	pubkey.Y.FillBytes(buf[32:])
	return uuid.NewSHA1(namespace, buf[:])
}
