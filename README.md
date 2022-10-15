# Bifrost

Bifrost is a tiny mTLS authentication toolkit.
The Go library can be used to fetch signed certificates from a bifrost issuer CA server.

![My First CA](docs/my-first-ca.jpg)

## Use library

Use bifrost to request a certificate from a Bifrost CA.

```go
import (
  "crypto/ecdsa"
  "crypto/elliptic"

  "github.com/RealImage/bifrost"
)

func main() {
  // TODO: handle errors
  key, _ := ecdsa.GenerateCertificate(elliptic.P256(), rand.Reader)
  crt, _ := bifrost.RequestSignature(context.Background(), "https://bifrost", key, nil)
  ...
}
```

## Certificate Authority

The bifrost Certificate Authority issues X.509 certificates for TLS client authentication.
Bifrost does not handle TLS termination or certificate verification.
API Gateway APIs in mTLS authentication mode is one tool that can handle both of these functions.

### Architecture

[issuer](cmd/issuer) signs certificates with a configured private key and self-signed certificate.
Certificate Requests must be signed with an ECDSA P256 Private Key
using the ECDSA SHA256 Signature Algorithm.

### Build

#### Go toolchain

`go build ./cmd/issuer`

#### Container

`podman build -t ghcr.io/RealImage/bifrost-ca --target=issuer .`

### Run CA

First create the CA material.
Then pass the certificate and private key as environment variables to the binary.

1. Create ECDSA P256 Private Key in PEM format:

        openssl ecparam -out key.pem -name prime256v1 -genkey -noout

2. Create 10 year self-signed certificate from the newly generated key:

        openssl req -new -key key.pem -x509 -nodes -days 3650 -out crt.pem

3. Then run the binary passing these new files along:

        ./issuer

4. Generate a client key, a CSR, and get it signed by the issuer:

        openssl ecparam -out clientkey.pem -name prime256v1 -genkey -noout
        openssl req -new -key clientkey.pem -sha256 -out csr.pem
        curl -X POST -H "Content-Type: text/plain" --data-binary "@csr.pem" localhost:8080 >clientcrt.pem

5. Admire your shiny new client certificate:

        openssl x509 -in clientcrt.pem -noout -text
