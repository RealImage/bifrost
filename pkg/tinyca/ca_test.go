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
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/RealImage/bifrost"
	"github.com/google/uuid"
)

var serveHTTPTests = []struct {
	accept        string
	contentType   string
	requestMethod string
	requestBody   []byte
	expectedCode  int
	expectedBody  []byte
}{
	// Good requests.
	{
		requestBody: []byte(`-----BEGIN CERTIFICATE REQUEST-----
MIIBGDCBwAIBADBeMS0wKwYDVQQDDCQ4YjlmY2E3OS0xM2UwLTUxNTctYjc1NC1m
ZjJlNGU5ODVjMzAxLTArBgNVBAoMJDAwMDAwMDAwLTAwMDAtMDAwMC0wMDAwLTAw
MDAwMDAwMDAwMDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABIRKO/ou3QfVp5Ym
aKyBForLVwIKx67Ts9q1tC2lyGXCTYhFAFpE8zBSq2NCWT1QaFBF4GBh4Ve4XNyH
f/l+B/agADAKBggqhkjOPQQDAgNHADBEAiAOhgfkcjs16H2ZNpNUiOJcS8P+mpiC
f+0l7+v5i1OW0AIgFft4Xc7mEo5XxJuHItDSf9lOxilweHpEVbv+zw0Uogs=
-----END CERTIFICATE REQUEST-----`),
		expectedCode: http.StatusOK,
	},
	{
		accept: mimeTypeBytes,
		requestBody: []byte(`-----BEGIN CERTIFICATE REQUEST-----
MIIBGDCBwAIBADBeMS0wKwYDVQQDDCQ4YjlmY2E3OS0xM2UwLTUxNTctYjc1NC1m
ZjJlNGU5ODVjMzAxLTArBgNVBAoMJDAwMDAwMDAwLTAwMDAtMDAwMC0wMDAwLTAw
MDAwMDAwMDAwMDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABIRKO/ou3QfVp5Ym
aKyBForLVwIKx67Ts9q1tC2lyGXCTYhFAFpE8zBSq2NCWT1QaFBF4GBh4Ve4XNyH
f/l+B/agADAKBggqhkjOPQQDAgNHADBEAiAOhgfkcjs16H2ZNpNUiOJcS8P+mpiC
f+0l7+v5i1OW0AIgFft4Xc7mEo5XxJuHItDSf9lOxilweHpEVbv+zw0Uogs=
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
		requestBody: []byte(`-----BEGIN CERTIFICATE REQUEST-----
MIIBGTCBwAIBADBeMS0wKwYDVQQDDCQ4YjlmY2E3OS0xM2UwLTUxNTctYjc1NC1m
ZjJlNGU5ODVjMzAxLTArBgNVBAoMJDAwMDAwMDAwLTAwMDAtMDAwMC0wMDAwLTAw
MDAwMDAwMDAwMDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABIRKO/ou3QfVp5Ym
aKyBForLVwIKx67Ts9q1tC2lyGXCTYhFAFpE8zBSq2NCWT1QaFBF4GBh4Ve4XNyH
f/l+B/agADAKBggqhkjOPQQDAgNIADBFAiEA9e4/Ntkgv8DB19EWs+BwLKnlA94V
a9rP0bn1HhVb/P8CIEMAqO2BWQ28M3Io0Wy+MTpqtX7/O1BAnSXT4BvZGUot
-----END CERTIFICATE REQUEST-----`),
	},
	{
		accept:        "application/json",
		requestMethod: http.MethodPost,
		requestBody: []byte(`-----BEGIN CERTIFICATE REQUEST-----
MIIBGTCBwAIBADBeMS0wKwYDVQQDDCQ4YjlmY2E3OS0xM2UwLTUxNTctYjc1NC1m
ZjJlNGU5ODVjMzAxLTArBgNVBAoMJDAwMDAwMDAwLTAwMDAtMDAwMC0wMDAwLTAw
MDAwMDAwMDAwMDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABIRKO/ou3QfVp5Ym
aKyBForLVwIKx67Ts9q1tC2lyGXCTYhFAFpE8zBSq2NCWT1QaFBF4GBh4Ve4XNyH
f/l+B/agADAKBggqhkjOPQQDAgNIADBFAiEA9e4/Ntkgv8DB19EWs+BwLKnlA94V
a9rP0bn1HhVb/P8CIEMAqO2BWQ28M3Io0Wy+MTpqtX7/O1BAnSXT4BvZGUot
-----END CERTIFICATE REQUEST-----`),
		expectedCode: http.StatusNotAcceptable,
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
MIIBGDCBwAIBADBeMS0wKwYDVQQDDCQ4YjlmY2E3OS0xM2UwLTUxNTctYjc1NC1m
ZjJlNGU5ODVjMzAxLTArBgNVBAoMJDAwMDAwMDAwLTAwMDAtMDAwMC0wMDAwLTAw
MDAwMDAwMDAwMDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABIRKO/ou3QfVp5Ym
aKyBForLVwIKx67Ts9q1tC2lyGXCTYhFAFpE8zBSq2NCWT1QaFBF4GBh4Ve4XNyH
f/l+B/agADAKBggqhkjOPQQDBANHADBEAiB50xScLE5smT/CVvnHCYIm69msOX3+
mgv/AEzrEMftJgIgJMVY2zEn/qS9M/yJb7IeSSWv9IbiHfP325aZsynerNg=
-----END CERTIFICATE REQUEST-----`),
		expectedCode: http.StatusBadRequest,
		expectedBody: []byte(
			"invalid certificate format: invalid signature algorithm ECDSA-SHA512, use ECDSA-SHA256 instead",
		),
	},
	{
		requestBody: []byte(`-----BEGIN CERTIFICATE REQUEST-----
MIIBGjCBwQIBADBfMS0wKwYDVQQDDCQ0NkJEMDZENy1COENELTQ0Q0MtQUIwOS1E
QTMwMUI1OTY0REIxLjAsBgNVBAoMJTAwMDAwMDAwLTAwMDAtMDAwMC0wMDAwLTAw
MDAwMDAwMDAwMDAwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASESjv6Lt0H1aeW
JmisgRaKy1cCCseu07PatbQtpchlwk2IRQBaRPMwUqtjQlk9UGhQReBgYeFXuFzc
h3/5fgf2oAAwCgYIKoZIzj0EAwIDSAAwRQIgeb1ei3tJ4OPnX3UXUs3zT9vXfX+1
2OzwaXuGWZq1lcICIQDRfRgkf6Kb9XJj3od161qwGG25y7bt2zxOnvoHY3QdkQ==
-----END CERTIFICATE REQUEST-----`),
		expectedCode: http.StatusBadRequest,
		expectedBody: []byte(
			"invalid certificate format, invalid bifrost namespace: invalid UUID length: 37",
		),
	},
	{
		requestBody: []byte(`-----BEGIN CERTIFICATE REQUEST-----
MIIBFzCBwAIBADBeMS0wKwYDVQQDDCQ0NUZBNzA5Ni01RTI2LTRCMEYtODJFOC0z
Q0E0RkMyOEQzQkUxLTArBgNVBAoMJDAwMDAwMDAwLTAwMDAtMDAwMC0wMDAwLTAw
MDAwMDAwMDAwMDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABIRKO/ou3QfVp5Ym
aKyBForLVwIKx67Ts9q1tC2lyGXCTYhFAFpE8zBSq2NCWT1QaFBF4GBh4Ve4XNyH
f/l+B/agADAKBggqhkjOPQQDAgNGADBDAh8n+tbz1NmD1YPuCVSpXv6F5+FGSC8n
/0VF8h3MlyMJAiAbtdpfYZElm0SMRfbVOGNVRxrurlXyENPSVzzgVx3MoQ==
-----END CERTIFICATE REQUEST-----`),
		expectedCode: http.StatusForbidden,
		expectedBody: []byte(
			"wrong namespace: subject common name is '45FA7096-5E26-4B0F-82E8-3CA4FC28D3BE' but should be '8b9fca79-13e0-5157-b754-ff2e4e985c30'",
		),
	},
	{
		requestBody: []byte(`-----BEGIN CERTIFICATE REQUEST-----
MIHrMIGRAgEAMC8xLTArBgNVBAMMJDg5N0U0QzZDLUVCRDUtNEE4OC04RDVFLTYx
M0QzNjczRTM0NDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABIRKO/ou3QfVp5Ym
aKyBForLVwIKx67Ts9q1tC2lyGXCTYhFAFpE8zBSq2NCWT1QaFBF4GBh4Ve4XNyH
f/l+B/agADAKBggqhkjOPQQDAgNJADBGAiEAil27xQI3XQqqoNXgPUMNpJUukVDD
FOioc6+qkAh+Sv8CIQDxi4eJOHAg3+eSnryb3zgsDIoGWcw3NRWI12Kwwr9Upw==
-----END CERTIFICATE REQUEST-----`),
		expectedCode: http.StatusBadRequest,
		expectedBody: []byte(`invalid certificate format: missing bifrost namespace`),
	},
	{
		requestBody: []byte(`-----BEGIN CERTIFICATE REQUEST-----
MIIBGTCBwAIBADBeMS0wKwYDVQQDDCRDMzM2QUIzMS05MDc5LTQ2MUMtOEJGRS01
N0E4NzFCRTVGQkExLTArBgNVBAoMJERGMTkwQjY5LThDOTAtNDlBMC04NjlGLTAx
NjFFMkVBQTIxQzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABIRKO/ou3QfVp5Ym
aKyBForLVwIKx67Ts9q1tC2lyGXCTYhFAFpE8zBSq2NCWT1QaFBF4GBh4Ve4XNyH
f/l+B/agADAKBggqhkjOPQQDAgNIADBFAiA0uztDACLPHPsATXkPN6YFWcKFOAec
z+LCMO8YSsF3wgIhAM0ELa3gPiGhSlAoPRxSeXUQ9dEOLOPWyXxaON+V2HJ4
-----END CERTIFICATE REQUEST-----`),
		expectedCode: http.StatusForbidden,
		expectedBody: []byte(
			`wrong namespace: 'df190b69-8c90-49a0-869f-0161e2eaa21c', use '00000000-0000-0000-0000-000000000000' instead`,
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

	id := bifrost.UUID(uuid.Nil, &key.PublicKey)

	// Create root certificate.
	template := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName:   id.String(),
			Organization: []string{uuid.Nil.String()},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	crtDer, err := x509.CreateCertificate(randReader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	crt, _ := x509.ParseCertificate(crtDer)
	ca, err := New(crt, key, time.Hour)
	if err != nil {
		t.Fatal(err)
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
			if ac := tc.accept; ac != "" {
				req.Header.Set(acHeader, ac)
			}
			if ct := tc.contentType; ct != "" {
				req.Header.Set(ctHeader, ct)
			}
			rr := httptest.NewRecorder()
			ca.ServeHTTP(rr, req)
			resp := rr.Result()

			if resp.StatusCode != tc.expectedCode {
				t.Fatalf("expected code: %d, actual: %d,\n\nbody:\n```\n%s\n```\n",
					tc.expectedCode, rr.Code, rr.Body.String())
			}
			if ac := resp.Header.Get(acHeader); ac != "" && tc.accept != "" && ac != tc.accept {
				t.Fatalf("expected response media type: %s, actual: %s\n", tc.accept, ac)
			}
			if ct := resp.Header.Get(ctHeader); ct != "" && tc.contentType != "" &&
				ct != tc.contentType {
				t.Fatalf("expected response Content-Type: %s, actual: %s\n", tc.contentType, ct)
			}
			respBody, _ := io.ReadAll(resp.Body)
			if exp := tc.expectedBody; len(exp) != 0 {
				if !bytes.Equal(exp, respBody) {
					t.Fatalf("expected body:\n```\n%s\n```\n\nactual body:\n```\n%s\n```\n",
						exp, string(respBody))
				}
			} else if resp.StatusCode < 300 {
				// If expected body is empty, check that the response body is valid.
				switch resp.Header.Get(ctHeader) {
				case "", mimeTypeText:
					// Check that the response body is a valid PEM block.
					if p, _ := pem.Decode(respBody); p == nil {
						t.Fatal("response body is not a valid PEM block")
					}
				case mimeTypeBytes:
					// Check that the response body is a valid DER certificate.
					if _, err := x509.ParseCertificate(respBody); err != nil {
						t.Fatal("response body is not a valid DER certificate: ", err)
					}
				default:
					t.Fatalf("unexpected Content-Type: %s\n", resp.Header.Get(ctHeader))

				}
			}
		})
	}
}
