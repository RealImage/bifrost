package bifrost

import (
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/google/uuid"
)

func TestParseCertificatePEM(t *testing.T) {
	crtPem := []byte(`-----BEGIN CERTIFICATE-----
MIIBXzCCAQagAwIBAgIIbgCYf13JG6wwCgYIKoZIzj0EAwIwFDESMBAGA1UEAwwJ
bG9jYWxob3N0MB4XDTIyMTIxODEwMzYxMloXDTIzMDExNzIwMzYxMlowLzEtMCsG
A1UEAxMkNWQ5MjcwYjMtMGRlZS01YTEwLWFlZTYtODZmNTBjMjVmOTY2MFkwEwYH
KoZIzj0CAQYIKoZIzj0DAQcDQgAEhEo7+i7dB9WnliZorIEWistXAgrHrtOz2rW0
LaXIZcJNiEUAWkTzMFKrY0JZPVBoUEXgYGHhV7hc3Id/+X4H9qMnMCUwDgYDVR0P
AQH/BAQDAgSwMBMGA1UdJQQMMAoGCCsGAQUFBwMCMAoGCCqGSM49BAMCA0cAMEQC
IEwVqNmlhjs5rQ7bNDL3fpQAx1dGsyIOvmY1quAOv6NFAiArHTGQXdZesArKfcN8
UES2yThq4L/iz9pd8n/TJyaheQ==
-----END CERTIFICATE-----`)
	wantID := uuid.MustParse("5d9270b3-0dee-5a10-aee6-86f50c25f966")
	wantCrt := &x509.Certificate{
		Raw: []byte{
			48, 130, 1, 95, 48, 130, 1, 6, 160, 3, 2, 1, 2, 2, 8,
			110, 0, 152, 127, 93, 201, 27, 172, 48, 10, 6, 8, 42, 134,
			72, 206, 61, 4, 3, 2, 48, 20, 49, 18, 48, 16, 6, 3, 85, 4, 3,
			12, 9, 108, 111, 99, 97, 108, 104, 111, 115, 116, 48, 30, 23,
			13, 50, 50, 49, 50, 49, 56, 49, 48, 51, 54, 49, 50, 90, 23,
			13, 50, 51, 48, 49, 49, 55, 50, 48, 51, 54, 49, 50, 90, 48, 47,
			49, 45, 48, 43, 6, 3, 85, 4, 3, 19, 36, 53, 100, 57, 50, 55, 48,
			98, 51, 45, 48, 100, 101, 101, 45, 53, 97, 49, 48, 45, 97, 101,
			101, 54, 45, 56, 54, 102, 53, 48, 99, 50, 53, 102, 57, 54, 54, 48,
			89, 48, 19, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8, 42, 134, 72,
			206, 61, 3, 1, 7, 3, 66, 0, 4, 132, 74, 59, 250, 46, 221, 7, 213,
			167, 150, 38, 104, 172, 129, 22, 138, 203, 87, 2, 10, 199, 174, 211,
			179, 218, 181, 180, 45, 165, 200, 101, 194, 77, 136, 69, 0, 90, 68,
			243, 48, 82, 171, 99, 66, 89, 61, 80, 104, 80, 69, 224, 96,
			97, 225, 87, 184, 92, 220, 135, 127, 249, 126, 7, 246, 163,
			39, 48, 37, 48, 14, 6, 3, 85, 29, 15, 1, 1, 255, 4, 4, 3, 2, 4,
			176, 48, 19, 6, 3, 85, 29, 37, 4, 12, 48, 10, 6, 8, 43, 6, 1, 5,
			5, 7, 3, 2, 48, 10, 6, 8, 42, 134, 72, 206, 61, 4, 3, 2, 3, 71, 0,
			48, 68, 2, 32, 76, 21, 168, 217, 165, 134, 59, 57, 173, 14, 219, 52,
			50, 247, 126, 148, 0, 199, 87, 70, 179, 34, 14, 190, 102, 53, 170,
			224, 14, 191, 163, 69, 2, 32, 43, 29, 49, 144, 93, 214, 94, 176, 10,
			202, 125, 195, 124, 80, 68, 182, 201, 56, 106, 224, 191, 226, 207,
			218, 93, 242, 127, 211, 39, 38, 161, 121,
		},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		PublicKeyAlgorithm: x509.ECDSA,
	}
	block, _ := pem.Decode(crtPem)
	id, crt, err := ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate(%s)\nunexpected error = %v", crtPem, err)
	}
	if id != wantID {
		t.Fatalf("ParseCertificate(%s) id = %v, want %v", crtPem, id, wantID)
	}
	if !crt.Equal(wantCrt) {
		t.Fatalf("ParseCertificate(%s) crt = %v, want %v", crtPem, crt, wantCrt)
	}
}
