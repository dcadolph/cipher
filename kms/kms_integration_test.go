//go:build integration

// Integration tests for the AWS KMS backend. Skipped unless
// CIPHER_TEST_KMS_ARN points at a usable KMS key. The integration CI
// job runs a LocalStack container, creates a KMS key inside it, and
// passes the ARN through this env var. Local runs can target real
// AWS or a LocalStack instance the same way.
package kms_test

import (
	"bytes"
	"context"
	"os"
	"testing"

	"github.com/dcadolph/cipher"
	"github.com/dcadolph/cipher/kms"
)

// TestKMSIntegrationRoundTrip encrypts a plaintext through cipher
// using the kms provider, then decrypts the bytes and verifies the
// round trip. Reads the target key ARN from CIPHER_TEST_KMS_ARN.
func TestKMSIntegrationRoundTrip(t *testing.T) {
	arn := os.Getenv("CIPHER_TEST_KMS_ARN")
	if arn == "" {
		t.Skip("set CIPHER_TEST_KMS_ARN to run aws kms integration tests")
	}

	kp, err := kms.NewProvider(arn)
	if err != nil {
		t.Fatalf("kms.NewProvider: %v", err)
	}

	plain := []byte("api_key: sk-kms-integration-2026\n")
	enc := cipher.NewEncoder(kp)
	ciphertext, err := enc.Encode(context.Background(), "secrets.yaml", plain)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if bytes.Contains(ciphertext, []byte("sk-kms-integration-2026")) {
		t.Fatal("plaintext leaked into ciphertext")
	}

	dec := cipher.NewDecoder()
	round, err := dec.Decode(context.Background(), "secrets.yaml", ciphertext)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !bytes.Equal(plain, round) {
		t.Errorf("round trip mismatch\n want: %q\n  got: %q", plain, round)
	}
}
