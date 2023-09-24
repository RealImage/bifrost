// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package asgard

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
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

const testHeader = "rctx-test"

func TestIdentifyNoTLS(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("this should panic but did not")
		}
	}()

	backendServer := httptest.NewServer(nil)
	defer backendServer.Close()
	backendUrl, _ := url.Parse(backendServer.URL)

	id := Identify(testHeader)(httputil.NewSingleHostReverseProxy(backendUrl))
	rr := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	id.ServeHTTP(rr, request)
}

func TestIdentify(t *testing.T) {
	randReader := rand.New(rand.NewSource(42))
	// generate key pair and certificate
	priv, err := ecdsa.GenerateKey(elliptic.P256(), randReader)
	if err != nil {
		t.Errorf("error generating private key %s", err)
	}
	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Errorf("error marshaling private key %s", err)
	}

	ns := uuid.MustParse("80485314-6c73-40ff-86c5-a5942a0f514f")
	identity := bifrost.UUID(ns, &priv.PublicKey)

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
	crtBytes, err := x509.CreateCertificate(randReader, &template, &template, priv.Public(), priv)
	if err != nil {
		t.Errorf("error creating certificate %s", err)
	}
	crtPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: crtBytes})
	keyPem := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})
	crt, err := tls.X509KeyPair(crtPem, keyPem)
	if err != nil {
		t.Errorf("error loading certificate %s", err)
	}

	// backend server handler checks if request has expected header
	backendServer := httptest.NewServer(
		http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			rctx := r.Header.Get(testHeader)
			if rctx == "" {
				t.Errorf("expected %s header in request", testHeader)
			}
			requestContext := RequestContext{}
			if err := json.Unmarshal([]byte(rctx), &requestContext); err != nil {
				t.Errorf("error unmarshaling request context %s", err)
			}
			if requestContext.ClientCertificate.Equal(crt.Leaf) {
				t.Errorf("unexpected certificate in request context header")
			}
		}),
	)
	defer backendServer.Close()
	backendUrl, err := url.Parse(backendServer.URL)
	if err != nil {
		t.Errorf("error parsing backedn url %s", err)
	}

	// bouncer wraps around a reverse proxy that proxies requests to the HTTP backend
	id := Identify(testHeader)(httputil.NewSingleHostReverseProxy(backendUrl))

	// TLS server accepts client requests requiring TLS client cert auth
	server := httptest.NewUnstartedServer(id)
	server.TLS = &tls.Config{
		ClientAuth: tls.RequireAnyClientCert,
	}
	server.StartTLS()
	defer server.Close()

	// add generated certs to client
	client := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates:       []tls.Certificate{crt},
				InsecureSkipVerify: true,
			},
		},
	}

	// create request to TLS server
	request, err := http.NewRequest(http.MethodGet, server.URL, nil)
	if err != nil {
		t.Errorf("error creating request %s", err)
	}

	if _, err := client.Do(request); err != nil {
		t.Errorf("error doing request %s", err)
	}
}
