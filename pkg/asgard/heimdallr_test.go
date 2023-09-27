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
	"reflect"
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
		headerValue:  `{"identity":{"sourceIp":"::1","userAgent":"curl/7.64.1","clientCert":{"clientCertPem":"LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUI0RENDQVlhZ0F3SUJBZ0lCQVRBS0JnZ3Foa2pPUFFRREFqQmVNUzB3S3dZRFZRUUtFeVE0TURRNE5UTXgKTkMwMll6Y3pMVFF3Wm1ZdE9EWmpOUzFoTlRrME1tRXdaalV4TkdZeExUQXJCZ05WQkFNVEpHSTVNamc1WkdFMwpMVGc0TVRNdE5URmxaQzA1TlRkaUxXSTJZbU0xWVRSa05qUXhOakFlRncweU16QTVNakF4T0RReU1EaGFGdzB5Ck16QTVNakF4T1RReU1EaGFNRjR4TFRBckJnTlZCQW9USkRnd05EZzFNekUwTFRaak56TXROREJtWmkwNE5tTTEKTFdFMU9UUXlZVEJtTlRFMFpqRXRNQ3NHQTFVRUF4TWtZamt5T0Rsa1lUY3RPRGd4TXkwMU1XVmtMVGsxTjJJdApZalppWXpWaE5HUTJOREUyTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFN3B5UGxZMERZWW03CjhEK0J1Z0tYck5EeFhuMk5mT2liQit3VjNJTUdCUmlMOEQ2cmhKdVRXY2dNVW1odVBJNlNzeTl5S2V4cHhOWVYKcnhzdndGODR1Nk0xTURNd0RnWURWUjBQQVFIL0JBUURBZ2VBTUJNR0ExVWRKUVFNTUFvR0NDc0dBUVVGQndNQgpNQXdHQTFVZEV3RUIvd1FDTUFBd0NnWUlLb1pJemowRUF3SURTQUF3UlFJaEFQWGVZSXFGUk9XS3BZckJ3TjlNCjk2cm1xUUpjQzkreCtOMG42UHpWZkI5NkFpQTVkLzNxMTZHRzIxOW1kU3BjMDVDdEZwWXA0Q1cvb1Z6bHdVUXQKYytncWNRPT0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=","issuerDN":"CN=b9289da7-8813-51ed-957b-b6bc5a4d6416,O=80485314-6c73-40ff-86c5-a5942a0f514f","serialNumber":"","subjectDN":"CN=b9289da7-8813-51ed-957b-b6bc5a4d6416,O=80485314-6c73-40ff-86c5-a5942a0f514f","validity":{"notAfter":"2023-09-20T19:42:08Z","notBefore":"2023-09-20T18:42:08Z"}}}}`,
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
				if !reflect.DeepEqual(rctx.ClientPublicKey, tc.expectedKey) {
					t.Errorf("expected key %v, got %v", tc.expectedKey, rctx.ClientPublicKey)
				}
				if !reflect.DeepEqual(rctx.Namespace, tc.expectedNs) {
					t.Errorf("expected namespace %v, got %v", tc.expectedNs, rctx.Namespace)
				}
			})).ServeHTTP(w, req)
			if w.Code != tc.expectedCode {
				t.Errorf("expected status %d, got %d", tc.expectedCode, w.Code)
			}
		})
	}
}
