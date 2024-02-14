package tinyca

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"math/rand"
	"mime"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/RealImage/bifrost"
	"github.com/RealImage/bifrost/internal/webapp"
	"github.com/google/uuid"
	"golang.org/x/net/html"
)

var (
	testns = uuid.Must(uuid.Parse("80485314-6C73-40FF-86C5-A5942A0F514F"))

	serveHTTPTests = []struct {
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
			accept: "application/octet-stream",
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
			accept: "text/plain",
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
			accept: "text/html",
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
			accept: "*/*",
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
			expectedCode:  http.StatusNotAcceptable,
			requestBody: []byte(`-----BEGIN CERTIFICATE REQUEST-----
MIIBGjCBwAIBADBeMS0wKwYDVQQDDCQwZjljMmFjNC1iZDdmLTU5MjMtYTc4NS1h
OGJjNGQ4ZTI4MzExLTArBgNVBAoMJDgwNDg1MzE0LTZDNzMtNDBGRi04NkM1LUE1
OTQyQTBGNTE0RjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABIRKO/ou3QfVp5Ym
aKyBForLVwIKx67Ts9q1tC2lyGXCTYhFAFpE8zBSq2NCWT1QaFBF4GBh4Ve4XNyH
f/l+B/agADAKBggqhkjOPQQDAgNJADBGAiEAqvq1FkgO02cZp4Etg1T0KzimcO2Y
l83jqe9OFH2tJOwCIQDpQGF56BlTZG70I6mLhNGq1wVMNclYHq2cVUTPl6iMmg==
-----END CERTIFICATE REQUEST-----`),
		},
		{
			expectedCode: http.StatusBadRequest,
			expectedBody: []byte("bifrost: error decoding certificate request PEM block"),
		},
		{
			contentType:  webapp.MimeTypeBytes,
			expectedCode: http.StatusBadRequest,
			expectedBody: []byte(
				"bifrost: certificate request invalid: asn1: syntax error: sequence truncated",
			),
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
				"bifrost: certificate request invalid: unsupported signature algorithm 'ECDSA-SHA512'",
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
				"bifrost: certificate request invalid: invalid identity namespace 00000000-0000-0000-0000-0000000000000: invalid UUID length: 37",
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
			expectedCode: http.StatusBadRequest,
			expectedBody: []byte(
				"bifrost: certificate request invalid: incorrect identity",
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
			expectedBody: []byte(
				"bifrost: certificate request invalid: missing identity namespace",
			),
		},
		{contentType: "text/vindaloo", expectedCode: http.StatusUnsupportedMediaType},
	}
)

func TestCA_ServeHTTP(t *testing.T) {
	randReader := rand.New(rand.NewSource(42))

	// Create new private key.
	key, err := bifrost.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	id := bifrost.UUID(testns, key.PublicKey())

	// Create root certificate.
	template := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName:   id.String(),
			Organization: []string{testns.String()},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDer, err := x509.CreateCertificate(
		randReader,
		&template,
		&template,
		key.PublicKey().PublicKey,
		key,
	)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certDer)
	if err != nil {
		t.Fatal(err)
	}

	bfCert, err := bifrost.NewCertificate(cert)
	if err != nil {
		t.Fatal(err)
	}

	ca, err := New(bfCert, key, time.Hour)
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
					t.Fatalf("expected body:\n```\n%s\n```\n\nactual body:\n```\n%s\n```\n",
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
					if cert.Namespace != testns {
						t.Fatalf("expected namespace: %s, actual: %s\n", testns, cert.Namespace)
					}
				case webapp.MimeTypeBytes:
					cert, err := bifrost.ParseCertificate(respBody)
					if err != nil {
						t.Fatal("response body is not a valid bifrost certificate: ", err)
					}
					if cert.Namespace != testns {
						t.Fatalf("expected namespace: %s, actual: %s\n", testns, cert.Namespace)
					}
				case webapp.MimeTypeHtml:
					_, err := html.Parse(resp.Body)
					if err != nil {
						t.Fatal("response body is not a valid HTML document: ", err)
					}
					// TODO: Check that the document contains a pv-certificate-viewer element.
				default:
					t.Fatalf("unexpected Content-Type: %s\n", resp.Header.Get(webapp.HeaderNameContentType))
				}
			}
		})
	}
}
