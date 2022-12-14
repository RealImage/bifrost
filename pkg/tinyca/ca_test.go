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

var testCases = []struct {
	contentType   string
	requestMethod string
	requestBody   []byte
	expectedCode  int
	expectedBody  []byte
}{
	// good request
	{
		requestBody: []byte(`-----BEGIN CERTIFICATE REQUEST-----
MIHpMIGRAgEAMC8xLTArBgNVBAMMJGY0MjhjYjJjLWU4N2QtNWU3NC04ODcwLTRh
OTNkZTJjMGZjMDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABE7LuwRmLiltBYWi
5JTvmNCX3+8WIugE7rfu/XdBr/a1by0Om8cuegaS3dydDPYdsu444Y0SO4fyg7VP
cxVE1segADAKBggqhkjOPQQDAgNHADBEAiBbytm3m7IC3jd5+6KO9BYeh1Pq5nnJ
bRPubf2g/+QjlwIgBDQQN7a1Y2hD8CwX/5Wl/NUL4518VNuptjUC83lYk3E=
-----END CERTIFICATE REQUEST-----`),
	},
	// bad
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
		expectedBody: []byte("unsupported signature algorithm: ECDSA-SHA512, use ECDSA-SHA256 instead\n"),
	},
	{
		requestBody: []byte(`-----BEGIN CERTIFICATE REQUEST-----
MIHIMHACAQAwDjEMMAoGA1UEAwwDYWJjMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcD
QgAEVJQBcKxJshLf1q7n2Ny82x8gSdCeORhzTx3UOMDwHB+z2w6jZpsnDYvU5rzz
brdUoaBjkA82y67IR2FOJajGDaAAMAoGCCqGSM49BAMCA0gAMEUCIQDOM2Un8MXG
EjA3auHdzeQX6BLlgCHP3A/q5nthVhB7KwIgOBb0xt0IOKEy7EVdn8QRA8FnmSwK
MpvZPekgC/o5cnM=
-----END CERTIFICATE REQUEST-----`),
		expectedCode: http.StatusForbidden,
		expectedBody: []byte(("subject common name is abc but should be 3d2f781d-f2ed-5891-a164-19e51ac9033a, wrong namespace?\n")),
	},
}

func TestCA_IssueCertificate(t *testing.T) {
	randReader := rand.New(rand.NewSource(42))

	// create new private key
	key, err := ecdsa.GenerateKey(elliptic.P256(), randReader)
	if err != nil {
		t.Fatal(err)
	}

	// create root certificate
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
		Crt: crt,
		Key: key,
	}

	for i, tc := range testCases {
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

			// default status code
			if tc.expectedCode == 0 {
				tc.expectedCode = http.StatusOK
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
