# ![Bifrost](docs/bifrost.png) Bifrost

[![Go Reference](https://pkg.go.dev/badge/github.com/RealImage/bifrost.svg)](https://pkg.go.dev/github.com/RealImage/bifrost)

A simple mTLS authentication toolkit.

[![CI 🏗](https://github.com/RealImage/bifrost/actions/workflows/ci.yml/badge.svg)](https://github.com/RealImage/bifrost/actions/workflows/ci.yml)

Bifrost consists of a Certificate Authority (CA) server that issues X.509 certificates,
a Go package to fetch such certificates, and a Go package with HTTP middleware
to identify and authenticate clients using such TLS certificates in requests.

Bifrost CA does not authenticate certificate signing
requests before issuance. You must authorise or control access to Bifrost CA as needed.

Bifrost CA issues certificates signed by a private key and a TLS X.509 certificate.
A TLS reverse proxy can use the issuing certificate to authenticate clients and secure
access to web applications.
Bifrost identifies clients uniquely by ECDSA public keys.
Client identity namespaces allow Bifrost to be natively multi-tenant.

## Releases

[![Release 🚀](https://github.com/RealImage/bifrost/actions/workflows/release.yml/badge.svg)](https://github.com/RealImage/bifrost/actions/workflows/release.yml)

Bifrost binaries are available for Windows, MacOS, and Linux on
the [releases](https://github.com/RealImage/bifrost/releases) page.

Container images are available at
[ghcr.io/realimage/bifrost](https://ghcr.io/realimage/bifrost).

## Identity

Bifrost identities are UUID version 5 UUIDs, derived from ECDSA public keys.
A client's identity is the sha1 hash of the namespace appended to the X and Y
curve points (big-endian) of its ECDSA P256 public key.

In pseudo-code,

`bifrostUUID = UUIDv5(sha1(NamespaceClientIdentity + PublicKey.X.Bytes() + PublicKey.Y.Bytes())`

## Build

### Native

Install Node.js & Go.
Build static binaries on your machine for all supported platforms.

```console
./build.sh
```

### Container

Build an image with [`ko`](https://ko.build).

```console
ko build --local ./cmd/bf
```

## Take Bifrost out for a spin

Here's what you need to get started.

1. Install all bifrost binaries by running `go install ./...`.
2. Generate a new namespace UUID using `export NS=$(bf new ns)`.
3. Ensure that python, curl, and openssl are available in your environment.

### Start CA server and mTLS reverse proxy

Set up server key material and start the CA and TLS reverse-proxy.

1. Create Bifrost ECDSA private key:

    `bf new id -o key.pem`

2. Create self-signed CA root certificate:

    `bf new ca -o cert.pem`

3. Start the CA issuer, reverse proxy, and the target web server.

    ```console
    bf ca &
    bf proxy &
    python -m http.server 8080 &
    ```

### Request a client certificate

1. Generate a new client identity key:

    `bf new key -o clientkey.pem`

2. Fetch signed certificate from the CA:

   ```console
   bf request -o clientcrt.pem
   ```

3. Make a request through the mTLS proxy to the python web server:

    `curl --cert clientcrt.pem --key clientkey.pem -k https://localhost:8443`

4. Admire your shiny new client certificate (optional):

   ```console
   $ openssl x509 -in clientcrt.pem -noout -text
    Certificate:
        Data:
            Version: 3 (0x2)
            Serial Number: 6573843113666499538 (0x5b3afb7b6f3d53d2)
        Signature Algorithm: ecdsa-with-SHA256
            Issuer: O=01881c8c-e2e1-4950-9dee-3a9558c6c741, CN=033fc353-f618-5c18-acd1-f9d4313cc052
            Validity
                Not Before: Jun 12 15:08:54 2024 GMT
                Not After : Jun 12 16:08:54 2024 GMT
            Subject: O=01881c8c-e2e1-4950-9dee-3a9558c6c741, CN=f6057aa6-6553-586a-9fda-319faa78958f
            Subject Public Key Info:
                Public Key Algorithm: id-ecPublicKey
                    Public-Key: (256 bit)
                    pub:
                        04:7a:88:ce:51:88:ac:8e:75:a4:17:79:0b:fe:6c:
                        ab:0c:89:be:fb:66:d7:e0:b2:b3:ec:e3:5d:02:4a:
                        cc:04:24:36:1f:33:64:8f:4d:61:aa:0a:ef:44:c3:
                        7b:60:7b:7d:48:ab:89:36:eb:d0:90:6e:d6:c1:78:
                        e7:52:82:9e:7f
                    ASN1 OID: prime256v1
                    NIST CURVE: P-256
            X509v3 extensions:
                X509v3 Key Usage: critical
                    Digital Signature, Key Encipherment
                X509v3 Extended Key Usage:
                    TLS Web Client Authentication
                X509v3 Basic Constraints: critical
                    CA:FALSE
                X509v3 Authority Key Identifier:
                    keyid:BD:BE:8A:D6:16:0A:08:46:01:27:71:25:42:04:60:DE:8C:23:8E:B3

        Signature Algorithm: ecdsa-with-SHA256
             30:45:02:21:00:f7:dd:97:18:ef:ec:95:e0:88:6e:d7:93:66:
             74:ca:4f:96:fe:34:b1:f8:0b:90:65:c0:bc:08:a3:49:fc:8f:
             37:02:20:6d:6a:fe:b5:d1:ab:77:59:3a:d1:94:6c:4c:f7:a2:
             3d:7f:69:a8:5e:85:52:aa:6b:7e:35:c4:9f:7e:11:92:d2
   ```

## Fishy Benchmarks

A toy benchmark for your favourite toy CA.

![Fishy Benchmark](docs/fishy-benchmark.jpg)

Bifrost CA issued 10,000 certificates on my Macbook Pro M1 Pro in ~41s.
Your results may vary.

## [LICENSE](LICENSE)

Bifrost is available under the terms of the MIT License.

Qube Cinema © 2023, 2024
