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

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
)

const getTImeout = time.Minute

// GetCertificate retrieves a PEM encoded certificate from uri.
func GetCertificate(ctx context.Context, uri string) (*x509.Certificate, error) {
	ctx, cancel := context.WithTimeout(ctx, getTImeout)
	defer cancel()

	crtPem, err := getPemFile(ctx, uri)
	if err != nil {
		return nil, fmt.Errorf("error getting file %s: %w", uri, err)
	}

	crt, err := x509.ParseCertificate(crtPem)
	if err != nil {
		return nil, fmt.Errorf("error parsing certificate uri %s: %w", uri, err)
	}

	return crt, nil
}

// GetPrivateKey retrieves a PEM encoded private key from uri.
func GetPrivateKey(ctx context.Context, uri string) (*ecdsa.PrivateKey, error) {
	ctx, cancel := context.WithTimeout(ctx, getTImeout)
	defer cancel()

	keyPem, err := getPemFile(ctx, uri)
	if err != nil {
		return nil, fmt.Errorf("error getting file %s: %w", uri, err)
	}

	key, err := x509.ParseECPrivateKey(keyPem)
	if err != nil {
		return nil, fmt.Errorf("error parsing key uri %s: %w", uri, err)
	}

	return key, nil
}

func getPemFile(ctx context.Context, uri string) ([]byte, error) {
	url, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}
	var pemData []byte
	switch s := url.Scheme; s {
	case "s3":
		pemData, err = getS3Key(ctx, url.Host, url.Path[1:])
	case "arn":
		pemData, err = getSecret(ctx, uri)
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
	return block.Bytes, nil
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
	return val.SecretBinary, nil
}
