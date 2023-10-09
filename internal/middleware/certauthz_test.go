package middleware

import (
	"context"
	"reflect"
	"testing"

	"github.com/aws/aws-lambda-go/events"
	"github.com/google/uuid"
)

type certAuthzTestCase struct {
	ns  uuid.UUID
	in  AuthenticatedRequestContext
	out events.APIGatewayCustomAuthorizerResponse
	err bool
}

var certAuthzTestCases = []certAuthzTestCase{
	{
		ns: uuid.MustParse("80485314-6c73-40ff-86c5-a5942a0f514f"),
		in: AuthenticatedRequestContext{
			APIGatewayCustomAuthorizerRequest: events.APIGatewayCustomAuthorizerRequest{
				MethodArn: "arn:aws:execute-api:us-east-1:123456789012:api-id/stage-name/GET/resource-path",
			},
			Authentication: Authentication{
				ClientCert: ClientCert{
					ClientCertPem: "-----BEGIN CERTIFICATE-----\nMIIB4DCCAYagAwIBAgIBATAKBggqhkjOPQQDAjBeMS0wKwYDVQQKEyQ4MDQ4NTMx\nNC02YzczLTQwZmYtODZjNS1hNTk0MmEwZjUxNGYxLTArBgNVBAMTJGI5Mjg5ZGE3\nLTg4MTMtNTFlZC05NTdiLWI2YmM1YTRkNjQxNjAeFw0yMzA5MjAxODQyMDhaFw0y\nMzA5MjAxOTQyMDhaMF4xLTArBgNVBAoTJDgwNDg1MzE0LTZjNzMtNDBmZi04NmM1\nLWE1OTQyYTBmNTE0ZjEtMCsGA1UEAxMkYjkyODlkYTctODgxMy01MWVkLTk1N2It\nYjZiYzVhNGQ2NDE2MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7pyPlY0DYYm7\n8D+BugKXrNDxXn2NfOibB+wV3IMGBRiL8D6rhJuTWcgMUmhuPI6Ssy9yKexpxNYV\nrxsvwF84u6M1MDMwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMB\nMAwGA1UdEwEB/wQCMAAwCgYIKoZIzj0EAwIDSAAwRQIhAPXeYIqFROWKpYrBwN9M\n96rmqQJcC9+x+N0n6PzVfB96AiA5d/3q16GG219mdSpc05CtFpYp4CW/oVzlwUQt\nc+gqcQ==\n-----END CERTIFICATE-----",
					IssuerDN:      "CN=b9289da7-8813-51ed-957b-b6bc5a4d6416,O=80485314-6c73-40ff-86c5-a5942a0f514f",
					SubjectDN:     "CN=b9289da7-8813-51ed-957b-b6bc5a4d6416,O=80485314-6c73-40ff-86c5-a5942a0f514f",
				},
			},
		},
		out: events.APIGatewayCustomAuthorizerResponse{
			PrincipalID: "b9289da7-8813-51ed-957b-b6bc5a4d6416",
			PolicyDocument: events.APIGatewayCustomAuthorizerPolicy{
				Version: "2012-10-17",
				Statement: []events.IAMPolicyStatement{
					{
						Action: []string{"execute-api:Invoke"},
						Effect: "Allow",
						Resource: []string{
							"arn:aws:execute-api:us-east-1:123456789012:api-id/stage-name/GET/resource-path",
						},
					},
				},
			},
			Context: map[string]interface{}{
				"namespace": "80485314-6c73-40ff-86c5-a5942a0f514f",
				"publicKey": "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"107927077086532896835579100061901814530678651729391130141381261794751161959704\",\"y\":\"63295961781010443906011747343675505672305089399194087223428542059136675690683\"}",
			},
		},
	},
	{
		in:  AuthenticatedRequestContext{},
		err: true,
	},
	{
		in: AuthenticatedRequestContext{
			Authentication: Authentication{
				ClientCert: ClientCert{
					ClientCertPem: "-----BEGIN CERTIFICATE REQUEST-----\nMIIBGTCBwAIBADBeMS0wKwYDVQQDDCQ3NmViZGJkNS1kYzQwLTU4YzEtYTEwMS0x\nY2U2YjBlZDllYjAxLTArBgNVBAoMJGQyNTdjMTY3LTFhOTgtNDkwZS04MWEzLWIz\nOTVmMWFiZmY3YTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABIRKO/ou3QfVp5Ym\naKyBForLVwIKx67Ts9q1tC2lyGXCTYhFAFpE8zBSq2NCWT1QaFBF4GBh4Ve4XNyH\nf/l+B/agADAKBggqhkjOPQQDAgNIADBFAiAaAejXa589rggsr3VHeTAkbi1ULSXw\njDIeM4TUVgM2cgIhAOy09QkVAYVeq2ksf6n/kCMm2CAZNX5wLjVzpRUCaD6T\n-----END CERTIFICATE REQUEST-----",
				},
			},
		},
		err: true,
	},
	{
		ns: uuid.MustParse("b9289da7-8813-51ed-957b-b6bc5a4d6416"),
		in: AuthenticatedRequestContext{
			APIGatewayCustomAuthorizerRequest: events.APIGatewayCustomAuthorizerRequest{
				MethodArn: "arn:aws:execute-api:us-east-1:123456789012:api-id/stage-name/GET/resource-path",
			},
			Authentication: Authentication{
				ClientCert: ClientCert{
					ClientCertPem: "-----BEGIN CERTIFICATE-----\nMIIB4DCCAYagAwIBAgIBATAKBggqhkjOPQQDAjBeMS0wKwYDVQQKEyQ4MDQ4NTMx\nNC02YzczLTQwZmYtODZjNS1hNTk0MmEwZjUxNGYxLTArBgNVBAMTJGI5Mjg5ZGE3\nLTg4MTMtNTFlZC05NTdiLWI2YmM1YTRkNjQxNjAeFw0yMzA5MjAxODQyMDhaFw0y\nMzA5MjAxOTQyMDhaMF4xLTArBgNVBAoTJDgwNDg1MzE0LTZjNzMtNDBmZi04NmM1\nLWE1OTQyYTBmNTE0ZjEtMCsGA1UEAxMkYjkyODlkYTctODgxMy01MWVkLTk1N2It\nYjZiYzVhNGQ2NDE2MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7pyPlY0DYYm7\n8D+BugKXrNDxXn2NfOibB+wV3IMGBRiL8D6rhJuTWcgMUmhuPI6Ssy9yKexpxNYV\nrxsvwF84u6M1MDMwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMB\nMAwGA1UdEwEB/wQCMAAwCgYIKoZIzj0EAwIDSAAwRQIhAPXeYIqFROWKpYrBwN9M\n96rmqQJcC9+x+N0n6PzVfB96AiA5d/3q16GG219mdSpc05CtFpYp4CW/oVzlwUQt\nc+gqcQ==\n-----END CERTIFICATE-----",
					IssuerDN:      "CN=b9289da7-8813-51ed-957b-b6bc5a4d6416,O=80485314-6c73-40ff-86c5-a5942a0f514f",
					SubjectDN:     "CN=b9289da7-8813-51ed-957b-b6bc5a4d6416,O=80485314-6c73-40ff-86c5-a5942a0f514f",
				},
			},
		},
		out: events.APIGatewayCustomAuthorizerResponse{
			PrincipalID: "b9289da7-8813-51ed-957b-b6bc5a4d6416",
			PolicyDocument: events.APIGatewayCustomAuthorizerPolicy{
				Version: "2012-10-17",
				Statement: []events.IAMPolicyStatement{
					{
						Action: []string{"execute-api:Invoke"},
						Effect: "Deny",
						Resource: []string{
							"arn:aws:execute-api:us-east-1:123456789012:api-id/stage-name/GET/resource-path",
						},
					},
				},
			},
		},
	},
}

func TestCertAuthorizer(t *testing.T) {
	for _, tc := range certAuthzTestCases {
		out, err := CertAuthorizer(tc.ns)(context.Background(), tc.in)
		if tc.err {
			if err == nil {
				t.Errorf("expected error, got nil")
			}
			continue
		}
		if err != nil {
			t.Errorf("unexpected error: %v", err)
			continue
		}
		if !reflect.DeepEqual(out, tc.out) {
			t.Errorf("expected %v, got %v", tc.out, out)
		}
	}
}
