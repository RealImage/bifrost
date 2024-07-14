package tinyca

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"math/rand"
	"mime"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/RealImage/bifrost"
	"github.com/RealImage/bifrost/internal/webapp"
	"github.com/google/uuid"
)

const validCsr = `-----BEGIN CERTIFICATE REQUEST-----
MIIBGjCBwAIBADBeMS0wKwYDVQQDDCQwZjljMmFjNC1iZDdmLTU5MjMtYTc4NS1h
OGJjNGQ4ZTI4MzExLTArBgNVBAoMJDgwNDg1MzE0LTZDNzMtNDBGRi04NkM1LUE1
OTQyQTBGNTE0RjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABIRKO/ou3QfVp5Ym
aKyBForLVwIKx67Ts9q1tC2lyGXCTYhFAFpE8zBSq2NCWT1QaFBF4GBh4Ve4XNyH
f/l+B/agADAKBggqhkjOPQQDAgNJADBGAiEAqvq1FkgO02cZp4Etg1T0KzimcO2Y
l83jqe9OFH2tJOwCIQDpQGF56BlTZG70I6mLhNGq1wVMNclYHq2cVUTPl6iMmg==
-----END CERTIFICATE REQUEST-----`

var (
	testNs = uuid.Must(uuid.Parse("80485314-6C73-40FF-86C5-A5942A0F514F"))

	serveHTTPTests = []struct {
		title         string
		gauntlet      Gauntlet
		accept        string
		contentType   string
		requestMethod string
		requestBody   []byte
		expectedCode  int
		expectedBody  []byte
	}{
		// Certificate requests are generated using the following command:
		//
		// export BF_NS=80485314-6C73-40FF-86C5-A5942A0F514F
		// openssl req -new \
		//   -key clientkey.pem -nodes \
		//   -subj "/CN=$(bfid clientkey.pem)/O=$BF_NS)" \
		//   -out clientcsr.pem
		//
		// Good requests.
		{
			title:        "ok",
			requestBody:  []byte(validCsr),
			expectedCode: http.StatusOK,
		},
		{
			title:        "should return a binary DER encoded certificate",
			accept:       "application/octet-stream",
			requestBody:  []byte(validCsr),
			expectedCode: http.StatusOK,
		},
		{
			title:       "should return a PEM encoded certificate",
			contentType: "text/plain; charset=utf-8",
			requestBody: []byte(`-----BEGIN CERTIFICATE REQUEST-----
MIIBGjCBwAIBADBeMS0wKwYDVQQDDCQwZjljMmFjNC1iZDdmLTU5MjMtYTc4NS1h
OGJjNGQ4ZTI4MzExLTArBgNVBAoMJDgwNDg1MzE0LTZDNzMtNDBGRi04NkM1LUE1
OTQyQTBGNTE0RjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABIRKO/ou3QfVp5Ym
aKyBForLVwIKx67Ts9q1tC2lyGXCTYhFAFpE8zBSq2NCWT1QaFBF4GBh4Ve4XNyH
f/l+B/agADAKBggqhkjOPQQDAgNJADBGAiEAqvq1FkgO02cZp4Etg1T0KzimcO2Y
l83jqe9OFH2tJOwCIQDpQGF56BlTZG70I6mLhNGq1wVMNclYHq2cVUTPl6iMmg==
-----END CERTIFICATE REQUEST-----`),
			expectedCode: http.StatusOK,
		},
		{
			title:        "should return a PEM encoded certificate HTML fragment",
			accept:       "text/html",
			requestBody:  []byte(validCsr),
			expectedCode: http.StatusOK,
		},
		{
			title:        "should return a PEM encoded certificate",
			accept:       "*/*",
			requestBody:  []byte(validCsr),
			expectedCode: http.StatusOK,
		},
		{
			title:         "return the default text/plain representation",
			accept:        "application/json",
			requestMethod: http.MethodPost,
			expectedCode:  http.StatusOK,
			requestBody:   []byte(validCsr),
		},
		// Bad.
		{
			title:        "we don't support JSON requests",
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
			title:        "empty request",
			expectedCode: http.StatusBadRequest,
			expectedBody: []byte("bifrost: error decoding certificate request PEM block"),
		},
		{
			title:        "invalid PEM block",
			contentType:  webapp.MimeTypeBytes,
			expectedCode: http.StatusBadRequest,
			expectedBody: []byte(
				"bifrost: certificate request invalid, asn1: syntax error: sequence truncated",
			),
		},
		{
			title: "invalid cert algorithm",
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
				"bifrost: certificate request invalid, unsupported signature algorithm 'ECDSA-SHA512'",
			),
		},
		{
			title: "empty namespace",
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
				"bifrost: certificate request invalid, invalid identity namespace 00000000-0000-0000-0000-0000000000000: invalid UUID length: 37",
			),
		},
		{
			title: "missing id",
			requestBody: []byte(`-----BEGIN CERTIFICATE REQUEST-----
MIIBFzCBwAIBADBeMS0wKwYDVQQDDCQ0NUZBNzA5Ni01RTI2LTRCMEYtODJFOC0z
Q0E0RkMyOEQzQkUxLTArBgNVBAoMJDAwMDAwMDAwLTAwMDAtMDAwMC0wMDAwLTAw
MDAwMDAwMDAwMDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABIRKO/ou3QfVp5Ym
aKyBForLVwIKx67Ts9q1tC2lyGXCTYhFAFpE8zBSq2NCWT1QaFBF4GBh4Ve4XNyH
f/l+B/agADAKBggqhkjOPQQDAgNGADBDAh8n+tbz1NmD1YPuCVSpXv6F5+FGSC8n
/0VF8h3MlyMJAiAbtdpfYZElm0SMRfbVOGNVRxrurlXyENPSVzzgVx3MoQ==
-----END CERTIFICATE REQUEST-----`),
			expectedCode: http.StatusBadRequest,
			expectedBody: []byte(
				"bifrost: certificate request invalid, incorrect identity",
			),
		},
		{
			title: "missing identity namespace",
			requestBody: []byte(`-----BEGIN CERTIFICATE REQUEST-----
MIHrMIGRAgEAMC8xLTArBgNVBAMMJDg5N0U0QzZDLUVCRDUtNEE4OC04RDVFLTYx
M0QzNjczRTM0NDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABIRKO/ou3QfVp5Ym
aKyBForLVwIKx67Ts9q1tC2lyGXCTYhFAFpE8zBSq2NCWT1QaFBF4GBh4Ve4XNyH
f/l+B/agADAKBggqhkjOPQQDAgNJADBGAiEAil27xQI3XQqqoNXgPUMNpJUukVDD
FOioc6+qkAh+Sv8CIQDxi4eJOHAg3+eSnryb3zgsDIoGWcw3NRWI12Kwwr9Upw==
-----END CERTIFICATE REQUEST-----`),
			expectedCode: http.StatusBadRequest,
			expectedBody: []byte(
				"bifrost: certificate request invalid, missing identity namespace",
			),
		},
		{
			title:       "gauntlet denied",
			requestBody: []byte(validCsr),
			gauntlet: func(_ context.Context, _ *bifrost.CertificateRequest) (*x509.Certificate, error) {
				return nil, errors.New("boo")
			},
			expectedCode: http.StatusForbidden,
			expectedBody: []byte("bifrost: certificate request denied, boo"),
		},
		{
			title:       "gauntlet timeout",
			requestBody: []byte(validCsr),
			gauntlet: func(ctx context.Context, _ *bifrost.CertificateRequest) (*x509.Certificate, error) {
				<-ctx.Done()
				return nil, nil
			},
			expectedCode: http.StatusServiceUnavailable,
			expectedBody: []byte("bifrost: certificate request aborted, gauntlet timed out"),
		},
	}
)

func TestCA_ServeHTTP(t *testing.T) {
	cert, key, err := createCACertKey()
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range serveHTTPTests {
		tc := tc

		t.Run(tc.title, func(t *testing.T) {
			t.Parallel()

			ca, err := New(cert, key, tc.gauntlet)
			if err != nil {
				t.Fatal(err)
			}
			defer ca.Close()

			method := http.MethodPost
			if tc.requestMethod != "" {
				method = tc.requestMethod
			}

			req, err := http.NewRequest(method, "/", bytes.NewReader(tc.requestBody))
			if err != nil {
				t.Fatal(err)
			}
			if ac := tc.accept; ac != "" {
				req.Header.Set(webapp.HeaderNameAccept, ac)
			}
			if ct := tc.contentType; ct != "" {
				req.Header.Set(webapp.HeaderNameContentType, ct)
			}

			rr := httptest.NewRecorder()
			ca.ServeHTTP(rr, req)
			resp := rr.Result()

			defer resp.Body.Close()

			if resp.StatusCode != tc.expectedCode {
				t.Fatalf("expected code: %d, actual: %d,\n\nbody:\n```\n%s\n```\n",
					tc.expectedCode, rr.Code, rr.Body.String())
			}
			if ac := resp.Header.Get(webapp.HeaderNameAccept); ac != "" && tc.accept != "" &&
				ac != tc.accept {
				t.Fatalf("expected response media type: %s, actual: %s\n", tc.accept, ac)
			}
			respBody, _ := io.ReadAll(resp.Body)
			if exp := tc.expectedBody; len(exp) != 0 {
				if !bytes.Equal(append(exp, "\n"...), respBody) {
					t.Fatalf("\nexpected body:\n```\n%s\n```\n\nactual body:\n```\n%s\n```\n",
						exp, string(respBody))
				}
			} else if resp.StatusCode < 300 {
				// If request succeeded and expected body is empty, check that the response body is valid.
				ct := resp.Header.Get(webapp.HeaderNameContentType)
				contentType, _, err := mime.ParseMediaType(ct)
				if err != nil {
					t.Fatalf("error parsing Content-Type header %s: %s", ct, err)
				}

				switch contentType {
				case "", webapp.MimeTypeText:
					b, _ := pem.Decode(respBody)
					if b == nil {
						t.Fatal("response body is not a valid PEM block")
						return
					}
					cert, err := bifrost.ParseCertificate(b.Bytes)
					if err != nil {
						t.Fatal("response body is not a valid bifrost certificate: ", err)
					}
					if cert.Namespace != testNs {
						t.Fatalf("expected namespace: %s, actual: %s\n", testNs, cert.Namespace)
					}
				case webapp.MimeTypeBytes:
					cert, err := bifrost.ParseCertificate(respBody)
					if err != nil {
						t.Fatal("response body is not a valid bifrost certificate: ", err)
					}
					if cert.Namespace != testNs {
						t.Fatalf("expected namespace: %s, actual: %s\n", testNs, cert.Namespace)
					}
				default:
					t.Fatalf("unexpected Content-Type: %s\n", resp.Header.Get(webapp.HeaderNameContentType))
				}
			}
		})
	}
}

func TestCA_gauntlet_panic(t *testing.T) {
	cert, key, err := createCACertKey()
	if err != nil {
		t.Fatal(err)
	}

	ca, err := New(
		cert,
		key,
		func(_ context.Context, _ *bifrost.CertificateRequest) (*x509.Certificate, error) {
			panic("boom")
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer ca.Close()

	rr := httptest.NewRecorder()
	req, err := http.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(validCsr)))
	if err != nil {
		t.Fatal(err)
	}

	ca.ServeHTTP(rr, req)
	resp := rr.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected code: %d, actual: %d\n", http.StatusInternalServerError, resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	expected := "bifrost: certificate request aborted, gauntlet panic('boom')\n"
	if !bytes.Equal([]byte(expected), body) {
		t.Fatalf("\nexpected body:\n```\n%s\n```\n\nactual body:\n```\n%s\n```\n", expected, body)
	}
}

func createCACertKey() (*bifrost.Certificate, *bifrost.PrivateKey, error) {
	randReader := rand.New(rand.NewSource(42))

	// Create new private key.
	key, err := bifrost.NewPrivateKey()
	if err != nil {
		return nil, nil, err
	}

	id := bifrost.UUID(testNs, key.PublicKey())

	template, err := CACertTemplate(testNs, id)
	if err != nil {
		return nil, nil, err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(time.Hour * 24)
	template.NotBefore = notBefore
	template.NotAfter = notAfter

	certDer, err := x509.CreateCertificate(
		randReader,
		template,
		template,
		key.PublicKey().PublicKey,
		key,
	)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(certDer)
	if err != nil {
		return nil, nil, err
	}

	bfCert, err := bifrost.NewCertificate(cert)
	if err != nil {
		return nil, nil, err
	}

	return bfCert, key, nil
}
