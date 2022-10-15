# Bifrost

Bifrost is a tiny mTLS authentication toolkit.
The Go library can be used to fetch signed certificates from a bifrost issuer CA server.

![My First CA](docs/my-first-ca.jpg)

## Namespaces & Identities

Namespaces allow bifrost to support multiple tenants easily.
Bifrost calls them identity namespaces because they are used to identify bifrost clients uniquely.
Names in a bifrost namespace are synthesized by appending the X and Y curve points
of a client's ecdsa P256 public key in binary big-endian form sequentially.

Client identities are generated as deterministic identities derived from private keys.
A key-pair's public key X and Y curve points are hashed along with the identity namespace.
The tuple of NamespaceID and Client Public Key will produce stable deterministic UUIDs.

In pseudo-code,

`newUUID = UUIDv5(sha1(NamespaceClientIdentity, PublicKey.X.Bytes() + PublicKey.Y.Bytes())`

## Use library

Use bifrost to request a certificate from a Bifrost CA.

```go
import (
  "crypto/ecdsa"
  "crypto/elliptic"

  "github.com/RealImage/bifrost"
)

// identity namespaces allow clients to use the same keys and authenticate with many bifrost CAs.
Namespace_ID = uuid.MustParse("b934ff92-44b5-4b66-a1d6-6bf91b20bb6d")

func main() {
  // TODO: handle errors
  idNamespace = uuid.Must()
  key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
  crt, _ := bifrost.RequestCertificate(context.Background(), "https://bifrost", Namespace_ID, key)
  ...
}
```

## Certificate Authority

The bifrost Certificate Authority issues X.509 certificates for TLS client authentication.
Bifrost does not handle TLS termination or certificate verification.
API Gateway APIs in mTLS authentication mode is one tool that can handle both of these functions.

### Architecture

Bifrost issuer takes care of issuing certificates signed by the single root certificate.
A web server that supports verifying TLS client certificates is required to implement
the remaining portion of the authentication system.

#### [`bfid`](cmd/bfid)

`bfid` returns the UUID for a private key.
If namespace isn't provided, NamespaceBifrost is used.

#### [`issuer`](cmd/issuer)

`issuer` signs certificates with a configured private key and self-signed certificate.
Certificate Requests must be signed with an ECDSA P256 Private Key
using the ECDSA SHA256 Signature Algorithm.

`issuer` can read the private key and root certificate in PEM form from files or s3.
It looks for `crt.pem` and `key.pem` in the same directory by default.

```bash
env CRT_URI=s3://bifrost-trust-store/crt.pem KEY_URI=./key.pem ./issuer
```

#### [AWS API Gateway HTTP API mTLS](https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-mutual-tls.html)

An AWS API Gateway HTTP API configured with a custom domain and mTLS authentication, work well with bifrost.
API Gateway mTLS expects an `s3://` uri that points to a PEM certificate bundle.
Client certificates must be signed with at least one of the certificates from the bundle.
This allows API Gateway and `issuer` to share the same certificate PEM bundle.

##### Key Rotation

Assume that an s3 bucket, `bifrost-trust-store` exists, with versioning turned on.

s3://bifrost-trust-store:

- crt.pem
- key.pem

crt.pem contains one or more PEM encoded root certificates.
key.pem contains exactly one PEM encoded private key that corresponds to the first certificate in crt.pem.

To replace the current signing certificate and key:

1. Create the new ECDSA key-pair and self-signed certificate.
2. Create a new revision of `s3://bifrost-trust-store/crt.pem` containing the new certificate as the first in the file.
3. Create a new revision of `s3://bifrost-trust-store/key.pem` replacing its contents entirely with that of the new key.

API Gateway will pick up the updated client trust bundle in crt.pem.
This allows it to trust certificates issued with the new certificate as well as any older certificates.
Bifrost issuer only uses the first certificate from crt.pem along with key.pem, so it will start issuing
certificates with the new root.

### Build

#### Go toolchain

`go build ./cmd/issuer`
`go build ./cmd/bifd`

#### Container

`podman build -t ghcr.io/RealImage/bifrost .`

### Run CA

First create the CA material.
Then pass the certificate and private key as environment variables to the binary.

1. Create ECDSA P256 Private Key in PEM format:

    `openssl ecparam -out key.pem -name prime256v1 -genkey -noout`

2. Create 10 year self-signed certificate from the newly generated key:

    `openssl req -new -key key.pem -x509 -nodes -days 3650 -out crt.pem`

3. Run the binary:

    `./issuer`

4. Generate a client key, a CSR, and get it signed by `issuer`:

    ```bash
    # ecdsa private key
    openssl ecparam -out clientkey.pem -name prime256v1 -genkey -noout

    # generate bifrost uuid
    ./bifd clientkey.pem

    # certificate signing request
    openssl req -new -key clientkey.pem -sha256 -subj "/CN=$(./bfid clientkey.pem)" -out csr.pem
  
    # fetch certificate
    curl -X POST -H "Content-Type: text/plain" --data-binary "@csr.pem" localhost:8080 >clientcrt.pem
    ```

5. Admire your shiny new client certificate:

    `openssl x509 -in clientcrt.pem -noout -text`
