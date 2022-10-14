package bifrost

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

var testCases = []struct {
	contentType  string
	requestBody  []byte
	expectedCode int
	expectedBody []byte
}{
	{
		expectedCode: http.StatusBadRequest,
	},
	{
		contentType:  ctPlain,
		requestBody:  []byte(""),
		expectedCode: http.StatusBadRequest,
	},
	{
		contentType: ctPlain,
		requestBody: []byte(`-----BEGIN CERTIFICATE REQUEST-----
MIHIMHACAQAwDjEMMAoGA1UEAwwDYWJjMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcD
QgAEVJQBcKxJshLf1q7n2Ny82x8gSdCeORhzTx3UOMDwHB+z2w6jZpsnDYvU5rzz
brdUoaBjkA82y67IR2FOJajGDaAAMAoGCCqGSM49BAMCA0gAMEUCIQDOM2Un8MXG
EjA3auHdzeQX6BLlgCHP3A/q5nthVhB7KwIgOBb0xt0IOKEy7EVdn8QRA8FnmSwK
MpvZPekgC/o5cnM=
-----END CERTIFICATE REQUEST-----`),
		expectedCode: http.StatusOK,
	},
	{
		contentType: ctPlain,
		requestBody: []byte(`-----BEGIN CERTIFICATE REQUEST-----
MIHJMHACAQAwDjEMMAoGA1UECgwDYXNkMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcD
QgAEVJQBcKxJshLf1q7n2Ny82x8gSdCeORhzTx3UOMDwHB+z2w6jZpsnDYvU5rzz
brdUoaBjkA82y67IR2FOJajGDaAAMAoGCCqGSM49BAMEA0kAMEYCIQD6EapmKs5z
cKRnf/olLAuHY8hax5LmWbCXrf870sdtJgIhAOvSL8kXbIqRGW1BV31cB2u+Fm2Z
kectkmknatSWyA0L
-----END CERTIFICATE REQUEST-----`),
		expectedCode: http.StatusBadRequest,
		expectedBody: []byte("unsupported signature algorithm: ECDSA-SHA512, use ECDSA-SHA256 instead\n"),
	},
}

func TestCA_IssueCertificate(t *testing.T) {
	randReader := rand.New(rand.NewSource(42))
	key, err := ecdsa.GenerateKey(elliptic.P256(), randReader)
	if err != nil {
		t.Fatal(err)
	}
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
	crt, err := x509.ParseCertificate(crtDer)
	if err != nil {
		t.Fatal(err)
	}

	ca := CA{
		Crt: *crt,
		Key: *key,
	}

	for i, tc := range testCases {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			req, err := http.NewRequest(http.MethodPost, "/", bytes.NewReader(tc.requestBody))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set(ctHeader, tc.contentType)
			rr := httptest.NewRecorder()
			ca.IssueCertificate(rr, req)
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
