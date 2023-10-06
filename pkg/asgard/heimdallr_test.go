// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package asgard

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
)

var testPubKey = &ecdsa.PublicKey{
	Curve: elliptic.P256(),
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
	headerName   string
	headerValue  string
	expectedCode int
	expectedKey  *ecdsa.PublicKey
	expectedNs   uuid.UUID
}{
	{
		headerValue:  `{"identity":{"sourceIp":"::1","userAgent":"curl/7.64.1","clientCert":{"clientCertPem":"-----BEGIN CERTIFICATE-----\nMIIB4DCCAYagAwIBAgIBATAKBggqhkjOPQQDAjBeMS0wKwYDVQQKEyQ4MDQ4NTMx\nNC02YzczLTQwZmYtODZjNS1hNTk0MmEwZjUxNGYxLTArBgNVBAMTJGI5Mjg5ZGE3\nLTg4MTMtNTFlZC05NTdiLWI2YmM1YTRkNjQxNjAeFw0yMzA5MjAxODQyMDhaFw0y\nMzA5MjAxOTQyMDhaMF4xLTArBgNVBAoTJDgwNDg1MzE0LTZjNzMtNDBmZi04NmM1\nLWE1OTQyYTBmNTE0ZjEtMCsGA1UEAxMkYjkyODlkYTctODgxMy01MWVkLTk1N2It\nYjZiYzVhNGQ2NDE2MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7pyPlY0DYYm7\n8D+BugKXrNDxXn2NfOibB+wV3IMGBRiL8D6rhJuTWcgMUmhuPI6Ssy9yKexpxNYV\nrxsvwF84u6M1MDMwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMB\nMAwGA1UdEwEB/wQCMAAwCgYIKoZIzj0EAwIDSAAwRQIhAPXeYIqFROWKpYrBwN9M\n96rmqQJcC9+x+N0n6PzVfB96AiA5d/3q16GG219mdSpc05CtFpYp4CW/oVzlwUQt\nc+gqcQ==\n-----END CERTIFICATE-----","issuerDN":"CN=b9289da7-8813-51ed-957b-b6bc5a4d6416,O=80485314-6c73-40ff-86c5-a5942a0f514f","serialNumber":"","subjectDN":"CN=b9289da7-8813-51ed-957b-b6bc5a4d6416,O=80485314-6c73-40ff-86c5-a5942a0f514f","validity":{"notAfter":"2023-09-20T19:42:08Z","notBefore":"2023-09-20T18:42:08Z"}}}}`,
		expectedKey:  testPubKey,
		expectedNs:   uuid.MustParse("80485314-6c73-40ff-86c5-a5942a0f514f"),
		expectedCode: http.StatusOK,
	},
	{
		headerName:   "foo",
		expectedCode: http.StatusUnauthorized,
	},
	{
		expectedCode: http.StatusUnauthorized,
	},
	{
		headerValue:  "invalid json",
		expectedCode: http.StatusUnauthorized,
	},
}

func TestHeimdallr(t *testing.T) {
	for i, tc := range heimdallrTestCases {
		t.Run(fmt.Sprintf("#%d", i), func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.headerName == "" {
				tc.headerName = testHeader
			}
			req.Header.Set(tc.headerName, tc.headerValue)
			w := httptest.NewRecorder()
			Heimdallr(testHeader)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				rctx := MustFromContext(r.Context())
				if key := rctx.ClientCert.PublicKey; !key.Equal(tc.expectedKey) {
					t.Errorf("expected key %v, got %v", tc.expectedKey, key)
				}
				if ns := rctx.ClientCert.Namespace; ns != tc.expectedNs {
					t.Errorf("expected namespace %v, got %v", tc.expectedNs, ns)
				}
			})).ServeHTTP(w, req)
			if w.Code != tc.expectedCode {
				t.Errorf("expected status %d, got %d", tc.expectedCode, w.Code)
			}
		})
	}
}
