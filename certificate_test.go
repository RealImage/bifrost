package bifrost

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"testing"

	"github.com/google/uuid"
)

type certVerifyTestCase struct {
	certPem []byte
	wantNS  uuid.UUID
	wantKey *ecdsa.PublicKey
	err     bool
}

var (
	t1X, _ = big.NewInt(0).
		SetString("59836456643741183269835176751095743515395817285058468900383880677655616972226", 10)
	t1Y, _ = big.NewInt(0).
		SetString("35068856771725771339387917164601956621562646129885199575367583771781073078262", 10)
)

var newCertTestCases = []certVerifyTestCase{
	{
		certPem: []byte(`-----BEGIN CERTIFICATE-----
MIIB+TCCAaCgAwIBAgIIeythG8hQTGcwCgYIKoZIzj0EAwIwXjEtMCsGA1UEAwwk
ZTk4OWEwOGMtYTBmOS01ZjZhLTk3NGUtMjA0YmMwOTBjMGI5MS0wKwYDVQQKDCQx
NTEyZGFhNC1kZGMxLTQxZDEtODY3My0zZmQxOWQyZjMzOGQwHhcNMjMwNzA5MTAz
MDQ0WhcNMjMwNzA5MTEzMDQ0WjBeMS0wKwYDVQQKEyQxNTEyZGFhNC1kZGMxLTQx
ZDEtODY3My0zZmQxOWQyZjMzOGQxLTArBgNVBAMTJDVkOTI3MGIzLTBkZWUtNWEx
MC1hZWU2LTg2ZjUwYzI1Zjk2NjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABIRK
O/ou3QfVp5YmaKyBForLVwIKx67Ts9q1tC2lyGXCTYhFAFpE8zBSq2NCWT1QaFBF
4GBh4Ve4XNyHf/l+B/ajSDBGMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggr
BgEFBQcDAjAfBgNVHSMEGDAWgBTKL5QNQ/ttAGYJUEyMH6O8we+Y9DAKBggqhkjO
PQQDAgNHADBEAiAkFsFf52lUWYaPPvmzm3EewrCud4Ju86Shy9Y4X/81NAIgKTYy
krCRDqY7/t+yGnvnBBIcam3xNWXnM9dk5v3DJss=
-----END CERTIFICATE-----`),
		wantNS: uuid.MustParse("1512daa4-ddc1-41d1-8673-3fd19d2f338d"),
		wantKey: &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     t1X,
			Y:     t1Y,
		},
	},
	{
		certPem: []byte(`-----BEGIN CERTIFICATE-----
MIIByjCCAW+gAwIBAgIUfkd7D26JbJ9Mp/VFcf3TU08FLs8wCgYIKoZIzj0EAwIw
LzEtMCsGA1UEAwwkZTk4OWEwOGMtYTBmOS01ZjZhLTk3NGUtMjA0YmMwOTBjMGI5
MB4XDTIzMDcwOTEyMDY0M1oXDTMzMDcwNjEyMDY0M1owLzEtMCsGA1UEAwwkZTk4
OWEwOGMtYTBmOS01ZjZhLTk3NGUtMjA0YmMwOTBjMGI5MFkwEwYHKoZIzj0CAQYI
KoZIzj0DAQcDQgAEE3ZBSXuPN/GSFf+E5n64Vtv5Nx+p1POAhBFmsWNrJJC9DaN7
wxsw4QHXGMhJd3ubg7586Me90qA/5dCM7By1t6NpMGcwHQYDVR0OBBYEFMovlA1D
+20AZglQTIwfo7zB75j0MB8GA1UdIwQYMBaAFMovlA1D+20AZglQTIwfo7zB75j0
MA8GA1UdEwEB/wQFMAMBAf8wFAYDVR0RBA0wC4IJbG9jYWxob3N0MAoGCCqGSM49
BAMCA0kAMEYCIQDRxLWl+65NwZoRo6KseZRu9VxFTGTBy4xtkLUc38bSigIhAMBu
ckSRr7kHaUL9xoMuU4i+nTB82BU2bMbPfYlmQVbP
-----END CERTIFICATE-----	`),
		err: true,
	},
	{
		certPem: []byte(`-----BEGIN CERTIFICATE-----
MIIB9zCCAZ2gAwIBAgIUFfA3Knmo4xH/PeaD2pq5QMq1MIgwCgYIKoZIzj0EAwIw
RjEtMCsGA1UEAwwkZTk4OWEwOGMtYTBmOS01ZjZhLTk3NGUtMjA0YmMwOTBjMGI5
MRUwEwYDVQQKDAxpbnZhbGlkIHV1aWQwHhcNMjMwNzA5MTIwNzQ2WhcNMzMwNzA2
MTIwNzQ2WjBGMS0wKwYDVQQDDCRlOTg5YTA4Yy1hMGY5LTVmNmEtOTc0ZS0yMDRi
YzA5MGMwYjkxFTATBgNVBAoMDGludmFsaWQgdXVpZDBZMBMGByqGSM49AgEGCCqG
SM49AwEHA0IABBN2QUl7jzfxkhX/hOZ+uFbb+TcfqdTzgIQRZrFjaySQvQ2je8Mb
MOEB1xjISXd7m4O+fOjHvdKgP+XQjOwctbejaTBnMB0GA1UdDgQWBBTKL5QNQ/tt
AGYJUEyMH6O8we+Y9DAfBgNVHSMEGDAWgBTKL5QNQ/ttAGYJUEyMH6O8we+Y9DAP
BgNVHRMBAf8EBTADAQH/MBQGA1UdEQQNMAuCCWxvY2FsaG9zdDAKBggqhkjOPQQD
AgNIADBFAiBeLNyabtR6uga1be7aDn07CvM7pYxZbh8r2jr0lMV/DwIhAOzV+rJt
BDwMT+LWnFoz19w+DW0Xzb0w1fCED8x7uRfO
-----END CERTIFICATE-----`),
		err: true,
	},
	{
		certPem: []byte(`-----BEGIN CERTIFICATE-----
MIICJzCCAc2gAwIBAgIUAZc+cEgo0f1cqlhlz4OFVNFTm9UwCgYIKoZIzj0EAwIw
XjEtMCsGA1UEAwwkZTk4OWEwOGMtYTBmOS01ZjZhLTk3NGUtMjA0YmMwOTBjMGI5
MS0wKwYDVQQKDCQ2RUY1NzdDNC0wNEFCLTQyQTktQTE0OS0xQjk3NkNFM0U2REIw
HhcNMjMwNzA5MTc0NjM5WhcNMzMwNzA2MTc0NjM5WjBeMS0wKwYDVQQDDCRlOTg5
YTA4Yy1hMGY5LTVmNmEtOTc0ZS0yMDRiYzA5MGMwYjkxLTArBgNVBAoMJDZFRjU3
N0M0LTA0QUItNDJBOS1BMTQ5LTFCOTc2Q0UzRTZEQjBZMBMGByqGSM49AgEGCCqG
SM49AwEHA0IABBN2QUl7jzfxkhX/hOZ+uFbb+TcfqdTzgIQRZrFjaySQvQ2je8Mb
MOEB1xjISXd7m4O+fOjHvdKgP+XQjOwctbejaTBnMB0GA1UdDgQWBBTKL5QNQ/tt
AGYJUEyMH6O8we+Y9DAfBgNVHSMEGDAWgBTKL5QNQ/ttAGYJUEyMH6O8we+Y9DAP
BgNVHRMBAf8EBTADAQH/MBQGA1UdEQQNMAuCCWxvY2FsaG9zdDAKBggqhkjOPQQD
AgNIADBFAiEAteaapen/h7mUQItKEIb4uYrXWv9uvuaRF++4xeHg9LsCIE1i53rC
m+cbVg9K0lG0SJlTp+qUz15lE6EGvZZOjaNR
-----END CERTIFICATE-----`),
		err: true,
	},
}

func TestNewCertificate(t *testing.T) {
	for ti, tc := range newCertTestCases {
		t.Run(fmt.Sprintf("#%d", ti), func(t *testing.T) {
			testNewCert(t, &tc)
		})
	}
}

func testNewCert(t *testing.T, tc *certVerifyTestCase) {
	var b []byte
	if block, _ := pem.Decode(tc.certPem); block != nil {
		b = block.Bytes
	}
	cert, err := x509.ParseCertificate(b)
	if !tc.err && err != nil {
		t.Fatalf("x509.ParseCertificate(%s)\nunexpected error = %v", tc.certPem, err)
	}
	if tc.err && err != nil {
		return
	}
	c, err := NewCertificate(cert)
	if !tc.err && err != nil {
		t.Fatalf("Certificate.Verify(%s)\n\nunexpected error = %v", tc.certPem, err)
	}
	if tc.err {
		if err != nil {
			return
		}
		t.Fatalf("ValidateCertificate(%s) err = nil, want error", tc.certPem)
	}
	if ns := c.Namespace; ns != tc.wantNS {
		t.Fatalf("ValidateCertificate(%s) ns = %v\nwant %v", tc.certPem, ns, tc.wantNS)
	}
	if key := c.PublicKey; !key.Equal(tc.wantKey) {
		t.Fatalf("ValidateCertificate(%s) key = %v\nwant %v", tc.certPem, key, tc.wantKey)
	}
}
