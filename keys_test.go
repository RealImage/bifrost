package bifrost

import "testing"

const testPrivKeyPemPkcs8 = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgKY7GC3pND13CjGYi
/U0bXQtfwJ+8VsS9wyc7yPg+lZyhRANCAASmpFKA12yjR2QwShSnDXz4YdIVr8LS
oFCWzK9ZiNV1DIYfbCr8GibUptSjDWLGAZ5P3+ZudoyCvnPYLR8ClmMH
-----END PRIVATE KEY-----
`

const testPubKeyPemPkix = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEpqRSgNdso0dkMEoUpw18+GHSFa/C
0qBQlsyvWYjVdQyGH2wq/Bom1KbUow1ixgGeT9/mbnaMgr5z2C0fApZjBw==
-----END PUBLIC KEY-----
`

func TestPublicKey_UnmarshalMarshalText(t *testing.T) {
	p := PublicKey{}
	if err := p.UnmarshalText([]byte(testPubKeyPemPkix)); err != nil {
		t.Fatal(err)
	}
	text, err := p.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	if string(text) != testPubKeyPemPkix {
		t.Fatalf("got %q, want %q", text, testPubKeyPemPkix)
	}
}

func TestPrivateKey_UnmarshalMarshalText(t *testing.T) {
	p := PrivateKey{}
	if err := p.UnmarshalText([]byte(testPrivKeyPemPkcs8)); err != nil {
		t.Fatal(err)
	}
	text, err := p.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	if string(text) != testPrivKeyPemPkcs8 {
		t.Fatalf("got %q, want %q", text, testPrivKeyPemPkcs8)
	}
}
