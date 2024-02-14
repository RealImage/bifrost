package asgard

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/RealImage/bifrost"
	"github.com/google/uuid"
)

var testPubKey = &bifrost.PublicKey{
	PublicKey: &ecdsa.PublicKey{
		Curve: elliptic.P256(),
	},
}

func init() {
	x := big.NewInt(0)
	y := big.NewInt(0)

	x.SetString(
		"107927077086532896835579100061901814530678651729391130141381261794751161959704",
		10,
	)
	y.SetString("63295961781010443906011747343675505672305089399194087223428542059136675690683", 10)

	testPubKey.X = x
	testPubKey.Y = y
}

var heimdallrTestCases = []struct {
	headerName   HeaderName
	headerValue  string
	expectedCode int
	expectedKey  *bifrost.PublicKey
	expectedNs   uuid.UUID
}{
	{
		headerValue: `-----BEGIN CERTIFICATE-----
MIICCTCCAa6gAwIBAgIIJDtozaMl9/EwCgYIKoZIzj0EAwIwXjEtMCsGA1UEAwwk
ODhhNWJmZDYtZTM0NC01ZDZmLTkzZjItZDQ2YWIyNjc5Y2FmMS0wKwYDVQQKDCRD
REZGNUUyMC0yRUFGLTRDOEMtOEE2MS05REU4N0U0QjlBRUEwHhcNMjQwMjE0MTkw
OTE0WhcNMjQwMjE1MTkwOTE0WjBeMS0wKwYDVQQKEyRjZGZmNWUyMC0yZWFmLTRj
OGMtOGE2MS05ZGU4N2U0YjlhZWExLTArBgNVBAMTJDFiMzliZDBlLTg2YmMtNTFk
NC05ZTg1LWNkNDIwMjliZDg5ODBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABIRK
O/ou3QfVp5YmaKyBForLVwIKx67Ts9q1tC2lyGXCTYhFAFpE8zBSq2NCWT1QaFBF
4GBh4Ve4XNyHf/l+B/ajVjBUMA4GA1UdDwEB/wQEAwIFoDATBgNVHSUEDDAKBggr
BgEFBQcDAjAMBgNVHRMBAf8EAjAAMB8GA1UdIwQYMBaAFMovlA1D+20AZglQTIwf
o7zB75j0MAoGCCqGSM49BAMCA0kAMEYCIQCM6LAeBJJcTEpJEGebMJa8MjT8lExN
8hUPmZRtz1ohqgIhALBm7YdRvg3NQbxR0rLqZ1yLIKZiLeLCBQHgOWIKm5dq
-----END CERTIFICATE-----`,
		expectedKey:  testPubKey,
		expectedNs:   uuid.MustParse("CDFF5E20-2EAF-4C8C-8A61-9DE87E4B9AEA"),
		expectedCode: http.StatusOK,
	},
	{
		headerValue:  ``,
		expectedNs:   uuid.MustParse("b9289da7-8813-51ed-957b-b6bc5a4d6416"),
		expectedCode: http.StatusForbidden,
	},
	{
		headerValue:  "invalid json",
		expectedCode: http.StatusServiceUnavailable,
	},
}

func TestHeimdallr(t *testing.T) {
	for i, tc := range heimdallrTestCases {
		t.Run(fmt.Sprintf("#%d", i), func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set(tc.headerName.String(), tc.headerValue)

			w := httptest.NewRecorder()

			hm := Heimdallr(tc.headerName, tc.expectedNs)
			handler := func(w http.ResponseWriter, r *http.Request) {
				cert, ok := ClientCert(r.Context())
				if !ok {
					t.Error("expected client certificate in request context")
					return
				}
				if ns := cert.Namespace; ns != tc.expectedNs {
					t.Errorf("expected namespace %v, got %v", tc.expectedNs, ns)
					return
				}
				if key := cert.PublicKey; !key.Equal(tc.expectedKey) {
					t.Errorf("expected key %v, got %v", tc.expectedKey, key)
					return
				}
			}

			hm(http.HandlerFunc(handler)).ServeHTTP(w, req)

			if w.Code != tc.expectedCode {
				t.Errorf("expected status %d, got %d", tc.expectedCode, w.Code)
			}
		})
	}
}
