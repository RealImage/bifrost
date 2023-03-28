# Bifrost

[![CI](https://github.com/RealImage/bifrost/actions/workflows/ci.yml/badge.svg)](https://github.com/RealImage/bifrost/actions/workflows/ci.yml)

![My First CA](docs/my-first-ca.jpg)

Bifrost brings simple mTLS authentication and transport encryption to web apps.
It identifies alients uniquely by mapping ECDSA public keys to UUIDs.
Bifrost CA namespaces are unique UUIDs. So one client public key may have
different UUIDs in different namespaces.

## Components

1. [`issuer`](#bouncercmdissuer) is a CA that issues client certificates.
2. [`bouncer`](#bouncercmdbouncer) is a HTTPS to HTTP proxy for local development.
3. [`bfid`](#bfidcmdbfid) prints the bifrost UUID for a certificate or key.
4. [`bifrost`](#bifrost-go) is a Go library for clients to fetch certificates.

Web apps that run on AWS Lambda with AWS API Gateway mTLS work with bouncer.

## Releases

Bifrost binaries are available on the [releases](https://github.com/RealImage/bifrost/releases)
page.
Container images are on <ghcr.io>.

[bifrost-bouncer](ghcr.io/realimage/bifrost-bouncer):

```console
podman pull ghcr.io/realimage/bifrost-bouncer
```

[bifrost-issuer](ghcr.io/realimage/bifrost-issuer):

```console
podman pull ghcr.io/realimage/bifrost-issuer
```

## Namespaces & Identities

Bifrost identity namespaces allow servers to associate different UUIDs with the
same clients.
Bifrost UUIDs are UUIDv5 deterministically created from the SHA1 hash
of a namespace UUID appended to the X and Y curve points in binary big-endian
from the client's ECDSA P256 public key.
The tuple of namespace UUID and client public key will always produce stable UUIDs.

In pseudo-code,

`bifrostUUID = UUIDv5(sha1(NamespaceClientIdentity, PublicKey.X.Bytes() + PublicKey.Y.Bytes())`

## Bifrost Go

Use `github.com/RealImage/bifrost` to request a certificate from a Bifrost CA
and parse Bifrost certificates.

## Certificate Authority

The bifrost Certificate Authority issues X.509 certificates for TLS client authentication.
Clients request short lived certificates based on unique key-paris by
sending a Certificate Signing Request signed by their public keys.
The CA signs the client's certificate if the UUID in the CSR subject is corrent.
This ensures that the client and server are operating within the same namespace.

### Architecture

Bifrost issuer takes care of issuing certificates signed by the signing certificate.
Bouncer can authenticate clients locally and proxy requests to a backend server.
In production, AWS API Gateway in mTLS mode can authenticate clients and proxy requests.
The aws-lambda-web-adapter extension also allows the backend server to be a
plain HTTP server.

#### [`bfid`](cmd/bfid)

`bfid` prints the Bifrost UUID of a certificate, public key, or private key.

#### [`bouncer`](cmd/bouncer)

`bouncer` is a TLS reverse proxy that authenticates requests using client certificates.
If a client authenticates, bouncer proxies requests to the backend url.

`bouncer` aims to mimic AWS API Gateway's mTLS mode.
It provides client TLS certificates in a HTTP header that mimics the format
followed by the [aws-lambda-web-adapter](https://github.com/awslabs/aws-lambda-web-adapter)
extension and the AWS API Gateway Request Context object.
`bouncer` adds the `x-amzn-request-context` header containing the client TLS certificate.

Sample Request Context containing Client Certificate:

```json
"requestContext": {
    "authentication": {
        "clientCert": {
            "clientCertPem": "-----BEGIN CERTIFICATE-----\nMIIEZTCCAk0CAQEwDQ...",
            "issuerDN": "C=US,ST=Washington,L=Seattle,O=Amazon Web Services,OU=Security,CN=My Private CA",
            "serialNumber": "1",
            "subjectDN": "C=US,ST=Washington,L=Seattle,O=Amazon Web Services,OU=Security,CN=My Client",
            "validity": {
                "notAfter": "Aug  5 00:28:21 2120 GMT",
                "notBefore": "Aug 29 00:28:21 2020 GMT"
            }
        }
    },
}
```

Run `bouncer` in front of a HTTP server listening on localhost port 5000:

```bash
env BACKEND_URL=http://127.0.0.1:5000 ./bouncer
```

References:

aws-lambda-web-adapter Request Context header: <https://github.com/awslabs/aws-lambda-web-adapter#request-context>

AWS API Gateway mTLS Authentication: <https://aws.amazon.com/blogs/compute/introducing-mutual-tls-authentication-for-amazon-api-gateway/>

#### [`issuer`](cmd/issuer)

`issuer` signs certificates with a configured private key and self-signed certificate.
Clients must send certificate requests signed by an ECDSA P256 private key
using the ECDSA SHA256 signature algorithm.

`issuer` can read the private key and root certificate in PEM form from a variety
of sources. It looks for `crt.pem` and `key.pem` in the same directory by default.

The `BF_NS` environment variable sets the Bifrost Identifier Namespace to use.
If unset, it defaults to `bifrost.Namespace`.

`issuer` exposes prometheus format metrics at the `/metrics` path.
Ir pushes metrics periodically to `METRICS_PUSH_URL` if set.

##### Examples

###### Run locally

Run `issuer` with a certificate from AWS S3 and a private key from a local file:

```bash
env CRT_URI=s3://bifrost-trust-store/crt.pem KEY_URI=./key.pem ./issuer
```

###### Zero Downtime Key Rotation

[AWS API Gateway HTTP API mTLS](https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-mutual-tls.html)

- crt.pem contains one or more PEM encoded root certificates stored in an S3 bucket.
- key.pem is the key that signed the first certificate in crt.pem, stored in AWS
  Secrets Manager.

To replace the current signing certificate and key:

1. Create the new ECDSA key-pair and self-signed certificate.
2. Create a new revision of `s3://bifrost-trust-store/crt.pem`, prepending the
   newly created certificate.

API Gateway will pick up the updated client trust bundle in crt.pem.
This allows it to trust certificates issued with the new certificate
alongside any previous certificates that may exist.
Bifrost issuer uses the first certificate from crt.pem along with key.pem.
Restarting issuer or reloading its configuration will cause it to start
using the new certificate.

### Build

#### Go toolchain

Build Go binaries on your machine:

```console
mkdir build
go build -o build ./...
```

#### Containers

bouncer:

```console
podman build -t gcr.io/realimage/bifrost-bouncer --target=bouncer .
```

issuer:

```console
podman build -t ghcr.io/realimage/bifrost-issuer --target=issuer .
```

### Run CA

`issuer` is the server and `curl` + `bfid` are the client.

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

    # certificate request with CommonName set to UUID of public key using `bfid`
    openssl req -new -key clientkey.pem -sha256 -subj "/CN=$(./bfid clientkey.pem)" -out csr.pem

    # fetch certificate
    curl -X POST -H "Content-Type: text/plain" --data-binary "@csr.pem" localhost:8888 >clientcrt.pem
    ```

5. Admire your shiny new client certificate:

    `openssl x509 -in clientcrt.pem -noout -text`

## Fishy Benchmarks

A toy benchmark for your favourite toy CA.

![my-first-benchmark.jpg](docs/my-first-benchmark%20(ca).jpg)

`issuer` issued 10,000 certificates on my Macbook Pro M1 Pro in ~41s.
The slowest request completed in 12ms.
With a mean response time of 4ms this is objectively the fastest CA on the planet.
Statisticians hate this one weird trick.
