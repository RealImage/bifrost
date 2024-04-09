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
		"59836456643741183269835176751095743515395817285058468900383880677655616972226",
		10,
	)
	y.SetString("35068856771725771339387917164601956621562646129885199575367583771781073078262", 10)

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
		headerValue:  "-----BEGIN%20CERTIFICATE-----%0AMIICCjCCAbCgAwIBAgIIH7lebxROSBQwCgYIKoZIzj0EAwIwXjEtMCsGA1UEAwwk%0AZWZlYmJmZGMtZWMwNi01NjNmLWI4ZjItYjM5M2I0MjBkNWFlMS0wKwYDVQQKDCQw%0AMTg4MUM4Qy1FMkUxLTQ5NTAtOURFRS0zQTk1NThDNkM3NDEwIBcNMjQwMjE0MTkz%0AMDM1WhgPMjEwOTExMTAyMzAwMDBaMF4xLTArBgNVBAoTJDAxODgxYzhjLWUyZTEt%0ANDk1MC05ZGVlLTNhOTU1OGM2Yzc0MTEtMCsGA1UEAxMkYWUyZTg5ZDUtZGFiYi01%0AYTE1LWJhOTAtZWZmYzgzZmI3NzY0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE%0AhEo7+i7dB9WnliZorIEWistXAgrHrtOz2rW0LaXIZcJNiEUAWkTzMFKrY0JZPVBo%0AUEXgYGHhV7hc3Id%2F+X4H9qNWMFQwDgYDVR0PAQH%2FBAQDAgWgMBMGA1UdJQQMMAoG%0ACCsGAQUFBwMCMAwGA1UdEwEB%2FwQCMAAwHwYDVR0jBBgwFoAUyi+UDUP7bQBmCVBM%0AjB+jvMHvmPQwCgYIKoZIzj0EAwIDSAAwRQIgOzVtg9kWc0BRJB2%2FJVDGAdjp6ozZ%0A5XuF6SBT%2FXd57OoCIQDiAXXDOGBHEoNxSo+oz20OzretMmtk6htl0UU1bzL6Lw==%0A-----END%20CERTIFICATE-----",
		expectedKey:  testPubKey,
		expectedNs:   uuid.MustParse("01881C8C-E2E1-4950-9DEE-3A9558C6C741"),
		expectedCode: http.StatusOK,
	},
	{
		headerValue:  "-----BEGIN%20CERTIFICATE-----%0AMIICCTCCAbCgAwIBAgIIUKQb43DFdCEwCgYIKoZIzj0EAwIwXjEtMCsGA1UEAwwk%0AZWZlYmJmZGMtZWMwNi01NjNmLWI4ZjItYjM5M2I0MjBkNWFlMS0wKwYDVQQKDCQw%0AMTg4MUM4Qy1FMkUxLTQ5NTAtOURFRS0zQTk1NThDNkM3NDEwIBcNMjQwMjE0MTkz%0ANDQwWhgPMjEwOTExMTAyMzAwMDBaMF4xLTArBgNVBAoTJDAxODgxYzhjLWUyZTEt%0ANDk1MC05ZGVlLTNhOTU1OGM2Yzc0MTEtMCsGA1UEAxMkYWUyZTg5ZDUtZGFiYi01%0AYTE1LWJhOTAtZWZmYzgzZmI3NzY0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE%0AhEo7+i7dB9WnliZorIEWistXAgrHrtOz2rW0LaXIZcJNiEUAWkTzMFKrY0JZPVBo%0AUEXgYGHhV7hc3Id%2F+X4H9qNWMFQwDgYDVR0PAQH%2FBAQDAgWgMBMGA1UdJQQMMAoG%0ACCsGAQUFBwMCMAwGA1UdEwEB%2FwQCMAAwHwYDVR0jBBgwFoAUyi+UDUP7bQBmCVBM%0AjB+jvMHvmPQwCgYIKoZIzj0EAwIDRwAwRAIgREgMNY2MSwKL3YVMyzgI4h%2F0%2F0au%0Acpzcvv0u+i6cXHYCIGNqQgPElDasZfpAqS50msAs7yeTtZvBb396sZ+ZgJtk%0A-----END%20CERTIFICATE-----",
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
