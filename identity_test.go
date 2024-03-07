package bifrost

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"
	"reflect"
	"testing"

	"github.com/google/uuid"
)

var (
	testPubkeyX        = big.NewInt(0)
	testPubkeyY        = big.NewInt(0)
	parseIdentityTests = []struct {
		in  string
		out *Identity
		err bool
	}{
		{"", nil, true},
		{" ", nil, true},
		{"a@b", nil, true},
		{`-----BEGIN CERTIFICATE-----
MIIB4TCCAYagAwIBAgIBAjAKBggqhkjOPQQDAjBeMS0wKwYDVQQKEyRmZDYyMzZi
MC1hYjkxLTQ3NjUtODE4OS1kYWMzMjgwMTllZTkxLTArBgNVBAMTJDA2N2FlMDZi
LTA0MDYtNTdmNi1hYzRhLTg4NmFlMThkYzgyNTAeFw0yNDAyMjgxNjEzMDdaFw0z
NDAyMjgwNDEzMDdaMF4xLTArBgNVBAoTJGZkNjIzNmIwLWFiOTEtNDc2NS04MTg5
LWRhYzMyODAxOWVlOTEtMCsGA1UEAxMkMDY3YWUwNmItMDQwNi01N2Y2LWFjNGEt
ODg2YWUxOGRjODI1MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE85VH+KmbdlRz
2/k6gZvdK3B65NNQTPzjSjHVXlHmO0SxvGrGizMF2VU6FZKb8c9IzLJCx4/3qaqT
gL21v/sWpqM1MDMwDgYDVR0PAQH/BAQDAgWgMBMGA1UdJQQMMAoGCCsGAQUFBwMB
MAwGA1UdEwEB/wQCMAAwCgYIKoZIzj0EAwIDSQAwRgIhAKwLCyc4byNa10gHSJ7I
uh75XFq3M40dR4eePB+Ps5tUAiEAyp7DYLOQdgo4jjqqSxGiEaPAFjUm4pb3jy8o
GvUI/Ag=
-----END CERTIFICATE-----`, &Identity{
			Namespace: uuid.MustParse("fd6236b0-ab91-4765-8189-dac328019ee9"),
			PublicKey: &PublicKey{
				&ecdsa.PublicKey{
					Curve: elliptic.P256(),
					X:     testPubkeyX,
					Y:     testPubkeyY,
				},
			},
		}, false},
	}
)

func init() {
	testPubkeyX.SetString(
		"110175779146304837965602249893703721020162570163908538740810842400734308612932",
		10,
	)
	testPubkeyY.SetString(
		"80392278385258085015574533217117941373830876037876176597277551479460057519782",
		10,
	)
}

func TestParseIdentity(t *testing.T) {
	for _, tt := range parseIdentityTests {
		identity, err := ParseIdentity([]byte(tt.in))
		if tt.err {
			if err == nil {
				t.Errorf("ParseIdentity(%q) expected error, got nil", tt.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseIdentity(%q) unexpected error: %#v", tt.in, err)
			continue
		}
		if !reflect.DeepEqual(identity, tt.out) {
			t.Errorf("ParseIdentity(%q) = %#v, want %#v", tt.in, identity, tt.out)
		}
	}
}
