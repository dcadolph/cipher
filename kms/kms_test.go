package kms_test

import (
	"context"
	"testing"

	"github.com/dcadolph/cipher/kms"
)

const (
	testARN1 = "arn:aws:kms:us-east-1:111111111111:key/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	testARN2 = "arn:aws:kms:us-east-1:111111111111:key/bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
)

// TestNewProviderPanicsOnEmpty verifies that the factory rejects empty
// input in both no-args and whitespace-only forms.
func TestNewProviderPanicsOnEmpty(t *testing.T) {
	t.Parallel()
	t.Run("no args", func(t *testing.T) {
		t.Parallel()
		defer func() {
			if r := recover(); r == nil {
				t.Fatal("expected panic on no ARNs")
			}
		}()
		_ = kms.NewProvider()
	})

	t.Run("only whitespace", func(t *testing.T) {
		t.Parallel()
		defer func() {
			if r := recover(); r == nil {
				t.Fatal("expected panic on whitespace-only ARNs")
			}
		}()
		_ = kms.NewProvider(" ", "")
	})
}

// TestKeyGroupsShape verifies KeyGroups produces a single group with
// one master key per ARN.
func TestKeyGroupsShape(t *testing.T) {
	t.Parallel()
	kp := kms.NewProvider(testARN1, testARN2)
	groups, err := kp.KeyGroups(context.Background())
	if err != nil {
		t.Fatalf("KeyGroups: %v", err)
	}
	if len(groups) != 1 {
		t.Fatalf("groups = %d, want 1", len(groups))
	}
	if len(groups[0]) != 2 {
		t.Fatalf("group size = %d, want 2", len(groups[0]))
	}
}

// TestNewProviderWithOptions verifies that options thread through to
// each master key.
func TestNewProviderWithOptions(t *testing.T) {
	t.Parallel()
	opts := kms.ProviderOptions{
		EncryptionContext: map[string]string{"app": "test"},
		Profile:           "test-profile",
		Role:              "arn:aws:iam::111111111111:role/test-role",
	}
	kp := kms.NewProviderWith(opts, testARN1)
	groups, err := kp.KeyGroups(context.Background())
	if err != nil {
		t.Fatalf("KeyGroups: %v", err)
	}
	if len(groups[0]) != 1 {
		t.Fatalf("group size = %d, want 1", len(groups[0]))
	}
}

// TestNewProviderFromCSV verifies parsing of a comma-separated list.
func TestNewProviderFromCSV(t *testing.T) {
	t.Parallel()
	kp := kms.NewProviderFromCSV(testARN1 + ", " + testARN2)
	groups, err := kp.KeyGroups(context.Background())
	if err != nil {
		t.Fatalf("KeyGroups: %v", err)
	}
	if len(groups[0]) != 2 {
		t.Fatalf("group size = %d, want 2", len(groups[0]))
	}
}
