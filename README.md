# Bifrost

[![CI](https://github.com/RealImage/bifrost/actions/workflows/ci.yml/badge.svg)](https://github.com/RealImage/bifrost/actions/workflows/ci.yml)

![My First CA](docs/my-first-ca.jpg)

Bifrost is a minimal Certificate Authority that issues X.509 certificates meant for
mTLS client authentication. Bifrost CA does not authenticate certificate signing
requests before issuance. You must authorise or control access to Bifrost CA as needed.

Bifrost CA issues certificates signed by a private key and TLS X.509 certificate.
A TLS reverse proxy can use the same certificate to authenticate clients and secure
access to web applications.
Bifrost identifies clients uniquely by mapping an ECDSA public key to a UUID deterministically.
Client identity namespaces allow Bifrost to be natively multi-tenant.

## Releases

Bifrost binaries are available on the [releases](https://github.com/RealImage/bifrost/releases)
page.
Container images are on ghcr.io.

[bifrost](ghcr.io/realimage/bifrost) contains all binaries.
Its intended for local development.

```console
podman pull ghcr.io/realimage/bifrost
```

[bifrost-ca](ghcr.io/realimage/bifrost-ca) contains the issuer binary.
The image has the [AWS Lambda Web Adapter](github.com/awslabs/aws-lambda-web-adapter)
extension installed.

```console
podman pull ghcr.io/realimage/bifrost-ca
```

## Identity

Bifrost UUIDs are UUIDv5 deterministically created from ECDSA public keys.
The namespace UUID appended to the X and Y curve points (big-endian) from
an ECDSA P256 public key hashed using SHA1 form the public key's UUID.
A public key will always map to a UUID within a namespace.

In pseudo-code,

`bifrostUUID = UUIDv5(sha1(NamespaceClientIdentity, PublicKey.X.Bytes() + PublicKey.Y.Bytes())`

## Components

## [`bf`](cmd/bf)

`bf` is an interactive tool that generates Bifrost CA material.
It uses [Charm Cloud] to securely store your key material securely in the cloud.

### [`bfid`](cmd/bfid)

`bfid` prints the Bifrost UUID of a certificate, public key, or private key.

### [`bouncer`](cmd/bouncer)

`bouncer` is a simple mTLS reverse proxy suitable for local development.
If client authentication succeeds, bouncer proxies the requests to the backend url.
The client's TLS certificate is available in the `x-amzn-request-context` header.

Sample Request Context containing Client Certificate:

```json
"requestContext": {
    "authentication": {
        "clientCert": {
            "clientCertPem": "-----BEGIN CERTIFICATE-----\nMIIEZTCCAk0CAQEwDQ...",
            "issuerDN": "C=IN,ST=Tamil Nadu,L=Chennai,O=Qube Cinema,OU=Qube Wire,CN=My Private CA",
            "serialNumber": "1",
            "subjectDN": "C=US,ST=Tamil Nadu,L=Chennai,O=Qube Cinema,OU=Qube Wire,CN=My Client",
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

### [`issuer`](cmd/issuer)

[OpenAPI schema](docs/issuer/openapi.yml)

`issuer` signs certificates with the configured certificate and its private key.
Clients must send certificate requests signed by an ECDSA P256 private key
using the ECDSA SHA256 signature algorithm.

`issuer` can read its signing certificate and private key in PEM form from a variety
of sources.
If unconfigured, it looks for `crt.pem` and `key.pem` in the current working directory.

The `BF_NS` environment variable sets the Bifrost Identifier Namespace to use.
If unset, it defaults to `bifrost.Namespace`.

`issuer` exposes prometheus format metrics at the `/metrics` path.

## Build

### Go toolchain

Build Go binaries on your machine:

```console
mkdir build
go build -o build ./...
```

### Containers

issuer:

```console
podman build -t ghcr.io/realimage/bifrost-ca --target=ca .
```

bifrost:

```console
podman build -t gcr.io/realimage/bifrost .
```

## Run Issuer CA

1. Create ECDSA P256 Private Key in PEM format:

    `openssl ecparam -out key.pem -name prime256v1 -genkey -noout`

2. Create 10 year self-signed certificate from the newly generated key:

    `openssl req -new -key key.pem -x509 -nodes -days 3650 -out crt.pem`

3. Run the binary:

    `./issuer`

4. Generate a new client key and CSR, and get it signed by `issuer`:

    `openssl ecparam -out clientkey.pem -name prime256v1 -genkey -noout`

5. Create a Certificate Signing Request using the new private key:

    `openssl req -new -key clientkey.pem -sha256 -subj "/CN=$(./bfid clientkey.pem)" -out csr.pem`

6. Fetch signed certificate from the CA:

    `curl -X POST -H "Content-Type: text/plain" --data-binary "@csr.pem" localhost:8888/issue >clientcrt.pem`

7. Admire your shiny new client certificate (optional):

    `openssl x509 -in clientcrt.pem -noout -text`

## Fishy Benchmarks

A toy benchmark for your favourite toy CA.

![my-first-benchmark.jpg](docs/my-first-benchmark%20(ca).jpg)

`issuer` issued 10,000 certificates on my Macbook Pro M1 Pro in ~41s.
The slowest request completed in 12ms.
With a mean response time of 4ms this is objectively the fastest CA on the planet.
Statisticians hate this one weird trick.

## [LICENSE](LICENSE)

Bifrost is available under the Mozilla Public License 2.0.

Qube Cinema © 2023
