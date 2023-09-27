// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// cafiles can fetch CA certificate and private key PEM files from many storage backends.
// PEM encoded CA files can be fetched from local filesystem, AWS S3, or AWS Secrets Manager.
package cafiles

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/url"
	"os"
	"time"

	"github.com/RealImage/bifrost"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/google/uuid"
)

const fetchTimeout = time.Minute

// GetCertificate returns a namespace and a bifrost certificate from uri.
// uri can be a relative or absolute file path, file://... uri, s3://... uri,
// or an AWS S3 or AWS Secrets Manager ARN.
// The certificate is validated before returning.
func GetCertificate(ctx context.Context, uri string) (uuid.UUID, *x509.Certificate, error) {
	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()

	crtPem, err := getPemFile(ctx, uri)
	if err != nil {
		return uuid.Nil, nil, fmt.Errorf("error getting file %s: %w", uri, err)
	}

	ns, crt, _, err := bifrost.ParseCertificate(crtPem.Bytes)
	if err != nil {
		return uuid.Nil, nil, fmt.Errorf("error validating certificate: %w", err)
	}

	return ns, crt, nil
}

// GetPrivateKey retrieves a PEM encoded private key from uri.
// uri can be one of a relative or absolute file path, file://... uri, s3://... uri,
// or an AWS S3 or AWS Secrets Manager ARN.
func GetPrivateKey(ctx context.Context, uri string) (*ecdsa.PrivateKey, error) {
	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()

	keyPem, err := getPemFile(ctx, uri)
	if err != nil {
		return nil, fmt.Errorf("error getting file %s: %w", uri, err)
	}

	var key *ecdsa.PrivateKey

	switch blockType := keyPem.Type; blockType {
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(keyPem.Bytes)
		if err != nil {
			return nil, fmt.Errorf("error parsing key uri %s: %w", uri, err)
		}
		key, ok := k.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("unexpected key type: %T", key)
		}
	case "EC PRIVATE KEY":
		if key, err = x509.ParseECPrivateKey(keyPem.Bytes); err != nil {
			return nil, fmt.Errorf("error parsing key uri %s: %w", uri, err)
		}
	}

	return key, nil
}

func getPemFile(ctx context.Context, uri string) (*pem.Block, error) {
	url, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("error parsing file uri %w", err)
	}
	var pemData []byte
	switch s := url.Scheme; s {
	case "s3":
		pemData, err = getS3Key(ctx, url.Host, url.Path[1:])
	case "arn":
		// s3 and secretsmanager arns are supported
		parsedArn, err := arn.Parse(uri)
		if err != nil {
			return nil, fmt.Errorf("error parsing arn %w", err)
		}
		switch svc := parsedArn.Service; svc {
		case "s3":
			pemData, err = getS3Key(ctx, url.Host, url.Path[1:])
		case "secretsmanager":
			pemData, err = getSecret(ctx, uri)
		default:
			return nil, fmt.Errorf("cannot load pem file from %s", svc)
		}
		if err != nil {
			return nil, fmt.Errorf("error fetching pem file: %w", err)
		}
	case "", "file":
		pemData, err = os.ReadFile(url.Path)
	default:
		return nil, fmt.Errorf("unsupported uri scheme %s", s)
	}
	if err != nil {
		return nil, fmt.Errorf("error fetching pem file: %w", err)
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("no pem data found")
	}
	return block, nil
}

var sess = session.Must(session.NewSessionWithOptions(session.Options{
	SharedConfigState: session.SharedConfigEnable,
}))

func getS3Key(ctx context.Context, bucket, key string) ([]byte, error) {
	rawObject, err := s3.New(sess).GetObjectWithContext(
		ctx,
		&s3.GetObjectInput{
			Bucket: aws.String(bucket),
			Key:    aws.String(key),
		})
	if err != nil {
		return nil, fmt.Errorf("error getting s3 object: %w", err)
	}

	body, err := io.ReadAll(rawObject.Body)
	if err != nil {
		return nil, err
	}
	return body, nil
}

func getSecret(ctx context.Context, secretARN string) ([]byte, error) {
	input := secretsmanager.GetSecretValueInput{SecretId: aws.String(secretARN)}
	val, err := secretsmanager.New(sess).GetSecretValueWithContext(ctx, &input)
	if err != nil {
		return nil, err
	}
	if val.SecretBinary != nil {
		return val.SecretBinary, nil
	}
	if val.SecretString != nil {
		return []byte(*val.SecretString), nil
	}
	return nil, fmt.Errorf("no secret data found")
}

type CrtKey struct {
	Ns  uuid.UUID
	Crt *x509.Certificate
	Key *ecdsa.PrivateKey
}

// GetCrtKey returns a namespace, certificate and private key from crtUri and keyUri.
func GetCrtKey(ctx context.Context, crtUri string, keyUri string) (*CrtKey, error) {
	ns, crt, err := GetCertificate(ctx, crtUri)
	if err != nil {
		return nil, fmt.Errorf("error getting crt: %w", err)
	}

	key, err := GetPrivateKey(ctx, keyUri)
	if err != nil {
		return nil, fmt.Errorf("error getting key: %w", err)
	}

	crtPubKey, ok := crt.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("error getting public key from certificate")
	}

	if crtPubKey.X.Cmp(key.X) != 0 || crtPubKey.Y.Cmp(key.Y) != 0 {
		return nil, fmt.Errorf("certificate and key do not match")
	}

	return &CrtKey{Ns: ns, Crt: crt, Key: key}, nil
}
