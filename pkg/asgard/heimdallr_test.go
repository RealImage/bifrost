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

	"github.com/RealImage/bifrost/internal/middleware"
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
		headerValue:  `{"authorizer":{"publicKey":"{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"107927077086532896835579100061901814530678651729391130141381261794751161959704\",\"y\":\"63295961781010443906011747343675505672305089399194087223428542059136675690683\"}","namespace":"80485314-6c73-40ff-86c5-a5942a0f514f"}}`,
		expectedKey:  testPubKey,
		expectedNs:   uuid.MustParse("80485314-6c73-40ff-86c5-a5942a0f514f"),
		expectedCode: http.StatusOK,
	},
	{
		headerValue:  `{"authorizer":{"publicKey":"{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"107927077086532896835579100061901814530678651729391130141381261794751161959704\",\"y\":\"63295961781010443906011747343675505672305089399194087223428542059136675690683\"}","namespace":"80485314-6c73-40ff-86c5-a5942a0f514f"}}`,
		expectedNs:   uuid.MustParse("b9289da7-8813-51ed-957b-b6bc5a4d6416"),
		expectedCode: http.StatusForbidden,
	},
	{
		headerName:   "foo",
		expectedCode: http.StatusServiceUnavailable,
	},
	{
		expectedCode: http.StatusServiceUnavailable,
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
			if tc.headerName == "" {
				tc.headerName = middleware.RequestContextHeaderName
			}
			req.Header.Set(tc.headerName, tc.headerValue)
			w := httptest.NewRecorder()
			h := Heimdallr(tc.expectedNs)
			h(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				id := MustFromContext(r.Context())
				if ns := id.Namespace; ns != tc.expectedNs {
					t.Errorf("expected namespace %v, got %v", tc.expectedNs, ns)
				}
				if key := id.PublicKey; !key.Equal(tc.expectedKey) {
					t.Errorf("expected key %v, got %v", tc.expectedKey, key)
				}
			}),
			).ServeHTTP(w, req)
			if w.Code != tc.expectedCode {
				t.Errorf("expected status %d, got %d", tc.expectedCode, w.Code)
			}
		})
	}
}
