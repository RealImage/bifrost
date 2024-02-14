package asgard

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"testing"
	"time"

	"github.com/RealImage/bifrost"
	"github.com/google/uuid"
)

func TestHofundNoTLS(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("this should panic but did not")
		}
	}()

	backendServer := httptest.NewServer(nil)
	defer backendServer.Close()
	backendUrl, _ := url.Parse(backendServer.URL)

	ti := Hofund(HeaderNameClientCert, uuid.Nil)(httputil.NewSingleHostReverseProxy(backendUrl))
	rr := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	ti.ServeHTTP(rr, request)
}

func TestHofund(t *testing.T) {
	randReader := rand.New(rand.NewSource(42))
	// generate key pair and certificate
	priv, err := bifrost.NewPrivateKey()
	if err != nil {
		t.Errorf("error generating private key %s", err)
	}

	ns := uuid.MustParse("80485314-6c73-40ff-86c5-a5942a0f514f")
	identity := priv.UUID(ns)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   identity.String(),
			Organization: []string{ns.String()},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	certBytes, err := x509.CreateCertificate(randReader, &template, &template, priv.Public(), priv)
	if err != nil {
		t.Errorf("error creating certificate %s", err)
	}
	certPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})

	privBytes, err := x509.MarshalECPrivateKey(priv.PrivateKey)
	if err != nil {
		t.Errorf("error marshaling private key %s", err)
	}
	keyPem := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})
	cert, err := tls.X509KeyPair(certPem, keyPem)
	if err != nil {
		t.Errorf("error loading certificate %s", err)
	}

	// backend server handler checks if request has expected header
	backendServer := httptest.NewServer(
		http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			escapedCertPem := r.Header.Get(HeaderNameClientCert.String())
			if escapedCertPem == "" {
				t.Errorf("expected %s header in request", HeaderNameClientCert)
				return
			}

			certPem, err := url.QueryUnescape(escapedCertPem)
			if err != nil {
				t.Errorf("error unescaping certificate %s", err)
				return
			}

			block, _ := pem.Decode([]byte(certPem))
			if block == nil {
				t.Errorf("error decoding certificate")
				return
			}

			cert, err := bifrost.ParseCertificate(block.Bytes)
			if err != nil {
				t.Errorf("error parsing certificate %s", err)
				return
			}

			if cert.Namespace != ns {
				t.Errorf("expected namespace %s, got %s", ns, cert.Namespace)
				return
			}

			if !cert.PublicKey.Equal(priv.PublicKey()) {
				t.Errorf("expected public key %v, got %v", priv.Public(), cert.PublicKey)
				return
			}
		}),
	)
	defer backendServer.Close()
	backendUrl, err := url.Parse(backendServer.URL)
	if err != nil {
		t.Errorf("error parsing backedn url %s", err)
	}

	hf := Hofund(HeaderNameClientCert, ns)(httputil.NewSingleHostReverseProxy(backendUrl))

	// TLS server accepts client requests requiring TLS client cert auth
	server := httptest.NewUnstartedServer(hf)
	server.TLS = &tls.Config{
		ClientAuth: tls.RequireAnyClientCert,
	}
	server.StartTLS()
	defer server.Close()

	// add generated certs to client
	client := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates:       []tls.Certificate{cert},
				InsecureSkipVerify: true,
			},
		},
	}

	// create request to TLS server
	request, err := http.NewRequest(http.MethodGet, server.URL, nil)
	if err != nil {
		t.Errorf("error creating request %s", err)
	}

	resp, err := client.Do(request)
	if err != nil {
		t.Errorf("error doing request %s", err)
	}
	defer resp.Body.Close()
}
