package bifrost

import "testing"

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

const testPrivKeyPemPkcs8 = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgrZfZw1jXZkDHsYXb
GbdftocRhSJK9Z5C0F9OT8PGKNShRANCAAQlCs+v1TsIPq1ZdYRKN/v+BWX/fzhC
nsWRaGNvP5b0ivW01Qt4RBLBMk1AU3OcCTMRphmIe4LHT1dk7sMOe3JS
-----END PRIVATE KEY-----
`

const testPrivKeyPemSec1 = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIK2X2cNY12ZAx7GF2xm3X7aHEYUiSvWeQtBfTk/DxijUoAoGCCqGSM49
AwEHoUQDQgAEJQrPr9U7CD6tWXWESjf7/gVl/384Qp7FkWhjbz+W9Ir1tNULeEQS
wTJNQFNznAkzEaYZiHuCx09XZO7DDntyUg==
-----END EC PRIVATE KEY-----
`

func TestPrivateKey_UnmarshalMarshalText(t *testing.T) {
	pkcs8Key := PrivateKey{}
	if err := pkcs8Key.UnmarshalText([]byte(testPrivKeyPemPkcs8)); err != nil {
		t.Fatal(err)
	}
	text, err := pkcs8Key.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	if string(text) != testPrivKeyPemPkcs8 {
		t.Fatalf("got %q, want %q", text, testPrivKeyPemPkcs8)
	}

	sec1Key := PrivateKey{}
	if err := sec1Key.UnmarshalText([]byte(testPrivKeyPemSec1)); err != nil {
		t.Fatal(err)
	}
	text, err = sec1Key.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	if string(text) != testPrivKeyPemPkcs8 {
		t.Fatalf("got %q, want %q", text, testPrivKeyPemPkcs8)
	}
}
