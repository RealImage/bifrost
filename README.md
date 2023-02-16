# Bifrost

[![CI](https://github.com/RealImage/bifrost/actions/workflows/ci.yaml/badge.svg)](https://github.com/RealImage/bifrost/actions/workflows/ci.yaml)

Bifrost is a tiny mutual TLS authentication toolkit comprising a Certificate Authority,
authentication library, and authenticating TLS reverse proxy.

The Certificate Authority service [`issuer`](#bouncercmdbouncer) issues signed certificates
to clients uniquely identified by individual ED25519 key-pairs.
Clients are identified by UUIDs that are determinstically produced from their public keys.
Key-pairs must be persisted to retain the same identity.
Certificates should be treated as ephemeral material.

The [`bifrost`](#bifrost-go) Go library fetches signed certificates from an issuer.

[`bouncer`](#bouncercmdbouncer) is a tiny mTLS authenticating reverse proxy meant for development.
HTTP servers running on AWS Lambda + AWS API Gateway mTLS will run behind bouncer unmodified.

![My First CA](docs/my-first-ca.jpg)

## Releases

Bifrost binaries are available on the [releases](https://github.com/RealImage/bifrost/releases) page.

Container images can be pulled from ghcr.io.

[bifrost-bouncer](ghcr.io/realimage/bifrost-bouncer):

```console
podman pull ghcr.io/realimage/bifrost-bouncer
```

[bifrost-issuer](ghcr.io/realimage/bifrost-issuer):

```console
podman pull ghcr.io/realimage/bifrost-issuer
```

## Namespaces & Identities

Identity Namespaces allow bifrost to support multiple tenants.
The combination of a Namespace and a Name must be universally unique.
Bifrost Identity names are synthesized from the SHA1 hash of the public key.
Specifically, names are synthesized by appending the X and Y curve points
of a client's ecdsa P256 public key in binary big-endian form sequentially.

The namespace and name are SHA1 hashed to produce the identity UUID.
The tuple of NamespaceID and Client Public Key will produce stable deterministic UUIDs.

In pseudo-code,

`bifrostUUID = UUIDv5(sha1(NamespaceClientIdentity, PublicKey.X.Bytes() + PublicKey.Y.Bytes())`

## Bifrost Go

Use `github.com/RealImage/bifrost` to request a certificate from a Bifrost CA and to parse Bifrost certificates.

## Certificate Authority

The bifrost Certificate Authority issues X.509 certificates for TLS client authentication.
Clients request short lived certificates based on unique key-paris by
sending a Certificate Signing Request signed by their public keys.
The CSR is signed only if the client's Bifrost UUID is present as the Subject.
This ensures that client and server are operating within the same namespace.

### Architecture

Bifrost issuer takes care of issuing certificates signed by the signing certificate.
A web server that supports verifying TLS client certificates is required to implement
the remaining portion of the authentication system. Bouncer is provided for local development.
The recommended production environment is a HTTP service running on AWS Lambda with
the aws-lambda-web-adapter extension behind an AWS API Gateway mTLS instance.

#### [`bfid`](cmd/bfid)

`bfid` prints the Bifrost UUID of a certificate, public key, or private key.

#### [`bouncer`](cmd/bouncer)

`bouncer` is a TLS reverse proxy that authenticates requests using client certificates.
Authenticated requests are proxied to the backend url.

`bouncer` aims to mimic AWS API Gateway's mTLS mode where the client's TLS certificate
is verified against a trust store configured for each instance of API Gateway.

The client's certificate is provided to AWS Lambda Functions in the Request Context object.
Qube Lambdas are usually written as plain HTTP servers running behind the
[aws-lambda-web-adapter](https://github.com/awslabs/aws-lambda-web-adapter) extension.
The web adapter extension passes the Lambda Request Context to our code in the
`x-amzn-request-context` header. Bifrost `bouncer` also adds this header to proxied requests.
When `bouncer` proxies the requests, only the `requestContext.authentication.clientCert`
object is populated.

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
Certificate Requests must be signed with an ECDSA P256 Private Key
using the ECDSA SHA256 Signature Algorithm.

`issuer` can read the private key and root certificate in PEM form from a variety of sources.
It looks for `crt.pem` and `key.pem` in the same directory by default.

The `BF_NS` environment variable sets the Bifrost Identifier Namespace to use.
If unset, `bifrost.Namespace` is used.

`issuer` exposes prometheus format metrics at the `/metrics` path.
This can be used as a health check endpoint for the service.
Metrics can also be pushed to your server using the `METRICS_PUSH_URL` environment variable.
`issuer` uses the Victoria Metrics [metrics](https://github.com/VictoriaMetrics/metrics) package.

Run `issuer` with a certificate from AWS S3 and a private key from a local file:

```bash
env CRT_URI=s3://bifrost-trust-store/crt.pem KEY_URI=./key.pem ./issuer
```

#### [AWS API Gateway HTTP API mTLS](https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-mutual-tls.html)

An AWS API Gateway HTTP API configured with a custom domain and mTLS authentication, work well with bifrost.
API Gateway mTLS expects an `s3://` uri that points to a PEM certificate bundle.
Client certificates must be signed with at least one of the certificates from the bundle.
This allows API Gateway and `issuer` to share the same certificate PEM bundle.

##### Zero Downtime Key Rotation

Assume that an s3 bucket, `bifrost-trust-store` exists, with versioning turned on.

s3://bifrost-trust-store:

- crt.pem

crt.pem contains one or more PEM encoded root certificates.

The corresponding private key for `crt.pem` is stored as in AWS Secrets Manager and identified
here as `key.pem`.
`key.pem` contains exactly one PEM encoded private key that pairs with the first certificate in `crt.pem`.

To replace the current signing certificate and key:

1. Create the new ECDSA key-pair and self-signed certificate.
2. Create a new revision of `s3://bifrost-trust-store/crt.pem` adding the new certificate as the first in the file, with older certificates immediately below it. Each cerificate should be separated by a newline.
3. Create a new revision of `key.pem` in Secrets Manager containing the newly generated key in PEM encoded ASN.1 DER form.

API Gateway will pick up the updated client trust bundle in crt.pem.
This allows it to trust certificates issued with the new certificate in addition to all of the previous certificates that may exist.
Bifrost issuer only uses the first certificate from crt.pem along with key.pem, so it will start issuing
certificates with the new root certificate once its configuration has been updated.

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
