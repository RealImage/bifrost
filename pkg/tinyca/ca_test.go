// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package tinyca

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

var serveHTTPTests = []struct {
	contentType   string
	requestMethod string
	requestBody   []byte
	expectedCode  int
	expectedBody  []byte
}{
	// Good request.
	{
		requestBody: []byte(`-----BEGIN CERTIFICATE REQUEST-----
MIHqMIGRAgEAMC8xLTArBgNVBAMMJDhiOWZjYTc5LTEzZTAtNTE1Ny1iNzU0LWZm
MmU0ZTk4NWMzMDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABIRKO/ou3QfVp5Ym
aKyBForLVwIKx67Ts9q1tC2lyGXCTYhFAFpE8zBSq2NCWT1QaFBF4GBh4Ve4XNyH
f/l+B/agADAKBggqhkjOPQQDAgNIADBFAiAvtaEUXg2tksT2Im9lcuwczo1kAkMi
t2JULLKqqzGD0QIhALfztii4QqqBBGDyS+oR2DMxvWjv68dGOnggr00I7T/S
-----END CERTIFICATE REQUEST-----`),
		expectedCode: http.StatusOK,
	},
	// Bad.
	{
		requestMethod: http.MethodGet,
		expectedCode:  http.StatusMethodNotAllowed,
	},
	{
		contentType:  "application/json",
		expectedCode: http.StatusUnsupportedMediaType,
	},
	{
		expectedCode: http.StatusBadRequest,
	},
	{
		requestBody:  []byte(""),
		expectedCode: http.StatusBadRequest,
	},
	{
		requestBody: []byte(`-----BEGIN CERTIFICATE REQUEST-----
MIHJMHACAQAwDjEMMAoGA1UECgwDYXNkMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcD
QgAEVJQBcKxJshLf1q7n2Ny82x8gSdCeORhzTx3UOMDwHB+z2w6jZpsnDYvU5rzz
brdUoaBjkA82y67IR2FOJajGDaAAMAoGCCqGSM49BAMEA0kAMEYCIQD6EapmKs5z
cKRnf/olLAuHY8hax5LmWbCXrf870sdtJgIhAOvSL8kXbIqRGW1BV31cB2u+Fm2Z
kectkmknatSWyA0L
-----END CERTIFICATE REQUEST-----`),
		expectedCode: http.StatusBadRequest,
		expectedBody: []byte("unsupported algorithm: ECDSA-SHA512, use ECDSA-SHA256 instead\n"),
	},
	{
		requestBody: []byte(`-----BEGIN CERTIFICATE REQUEST-----
MIHpMIGRAgEAMC8xLTArBgNVBAMMJDVkOTI3MGIzLTBkZWUtNWExMC1hZWU2LTg2
ZjUwYzI1Zjk2NjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABIRKO/ou3QfVp5Ym
aKyBForLVwIKx67Ts9q1tC2lyGXCTYhFAFpE8zBSq2NCWT1QaFBF4GBh4Ve4XNyH
f/l+B/agADAKBggqhkjOPQQDAgNHADBEAiAfjiRF70ApnjFwdvDDgyJ2/FGYUrOD
wmh3IsN75x4y9gIgCaVJQFe7OO8GzI2n2mLu75WOhil8xFcJYFwNp9JOORk=
-----END CERTIFICATE REQUEST-----`),
		expectedCode: http.StatusForbidden,
		expectedBody: []byte("subject common name is 5d9270b3-0dee-5a10-aee6-86f50c25f966 but " +
			"should be 8b9fca79-13e0-5157-b754-ff2e4e985c30, wrong namespace?\n",
		),
	},
}

func TestCA_ServeHTTP(t *testing.T) {
	randReader := rand.New(rand.NewSource(42))

	// Create new private key.
	key, err := ecdsa.GenerateKey(elliptic.P256(), randReader)
	if err != nil {
		t.Fatal(err)
	}

	// Create root certificate.
	template := x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Issuer Test CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 180),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	crtDer, err := x509.CreateCertificate(randReader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	crt, _ := x509.ParseCertificate(crtDer)
	ca := CA{
		crt: crt,
		key: key,
	}

	for i, tc := range serveHTTPTests {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			method := http.MethodPost
			if tc.requestMethod != "" {
				method = tc.requestMethod
			}

			req, err := http.NewRequest(method, "/", bytes.NewReader(tc.requestBody))
			if err != nil {
				t.Fatal(err)
			}
			if ct := tc.contentType; ct != "" {
				req.Header.Set(ctHeader, ct)
			}
			rr := httptest.NewRecorder()
			ca.ServeHTTP(rr, req)
			resp := rr.Result()

			if ct := resp.Header.Get(ctHeader); ct != "" && ct != tc.contentType {
				t.Fatalf("expected response Content-Type %s, actual %s\n", tc.contentType, ct)
			}

			if resp.StatusCode != tc.expectedCode {
				t.Fatalf("expected code %d, actual code %d,\n\nbody:\n```\n%s\n```\n",
					tc.expectedCode, rr.Code, rr.Body.String())
			}

			respBody, _ := io.ReadAll(resp.Body)
			if exp := tc.expectedBody; len(exp) != 0 {
				if !bytes.Equal(exp, respBody) {
					t.Fatalf("expected body:\n```\n%s\n```\n\nactual body:\n```\n%s\n```\n",
						exp, string(respBody))
				}
			}
		})
	}
}
