// cafiles can fetch CA certificate and private key PEM files from many storage backends.
// PEM encoded CA files can be fetched from local filesystem, AWS S3, or AWS Secrets Manager.
package cafiles

import (
	"context"
	"encoding/pem"
	"fmt"
	"io"
	"net/url"
	"os"

	"github.com/RealImage/bifrost"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

// GetCertificate returns a namespace and a bifrost certificate from uri.
// uri can be a relative or absolute file path, file://... uri, s3://... uri,
// or an AWS S3 or AWS Secrets Manager ARN.
// The certificate is validated before returning.
func GetCertificate(ctx context.Context, uri string) (*bifrost.Certificate, error) {
	certPem, err := getPemFile(ctx, uri)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(certPem)
	if block == nil {
		return nil, fmt.Errorf("expected PEM block")
	}

	cert, err := bifrost.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error validating certificate: %w", err)
	}

	return cert, nil
}

// GetPrivateKey retrieves a PEM encoded private key from uri.
// uri can be one of a relative or absolute file path, file://... uri, s3://... uri,
// or an AWS S3 or AWS Secrets Manager ARN.
// The private key can either be PEM encoded PKCS#8 or SEC1, ASN.1 DER form.
func GetPrivateKey(ctx context.Context, uri string) (*bifrost.PrivateKey, error) {
	pemData, err := getPemFile(ctx, uri)
	if err != nil {
		return nil, fmt.Errorf("error getting file %s: %w", uri, err)
	}

	var key bifrost.PrivateKey
	if err := key.UnmarshalText(pemData); err != nil {
		return nil, fmt.Errorf("error parsing private key: %w", err)
	}
	return &key, nil
}

func getPemFile(ctx context.Context, uri string) ([]byte, error) {
	url, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("error parsing file uri %w", err)
	}

	var pemData []byte
	switch s := url.Scheme; s {
	case "s3":
		pemData, err = getS3Key(ctx, url.Host, url.Path[1:])
	case "", "file":
		pemData, err = os.ReadFile(url.Path)
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
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported uri scheme %s", s)
	}

	if err != nil {
		return nil, err
	}

	return pemData, nil
}

func getS3Key(ctx context.Context, bucket, key string) ([]byte, error) {
	sdkConfig, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("error loading aws config: %w", err)
	}

	rawObject, err := s3.NewFromConfig(sdkConfig).GetObject(ctx,
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
	sdkConfig, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("error loading aws config: %w", err)
	}
	input := secretsmanager.GetSecretValueInput{SecretId: aws.String(secretARN)}

	val, err := secretsmanager.NewFromConfig(sdkConfig).GetSecretValue(ctx, &input)
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

// GetCertKey returns a bifrost certificate and private key from certUri and keyUri.
func GetCertKey(
	ctx context.Context,
	certUri string,
	keyUri string,
) (*bifrost.Certificate, *bifrost.PrivateKey, error) {
	cert, err := GetCertificate(ctx, certUri)
	if err != nil {
		return nil, nil, fmt.Errorf("error getting cert: %w", err)
	}

	key, err := GetPrivateKey(ctx, keyUri)
	if err != nil {
		return nil, nil, fmt.Errorf("error getting key: %w", err)
	}

	if !cert.IssuedTo(key.PublicKey()) {
		return nil, nil, fmt.Errorf("certificate and key do not match")
	}
	return cert, key, nil
}
