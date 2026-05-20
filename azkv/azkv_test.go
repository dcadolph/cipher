package azkv_test

import (
	"context"
	"testing"

	"github.com/dcadolph/cipher/azkv"
)

const (
	testURL1 = "https://myvault.vault.azure.net/keys/mykey/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testURL2 = "https://myvault.vault.azure.net/keys/another/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// TestNewProviderPanicsOnEmpty verifies that the factory rejects empty input.
func TestNewProviderPanicsOnEmpty(t *testing.T) {
	t.Parallel()
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on no URLs")
		}
	}()
	_ = azkv.NewProvider()
}

// TestNewProviderEMalformed verifies the error-returning constructor surfaces
// URL parsing errors.
func TestNewProviderEMalformed(t *testing.T) {
	t.Parallel()
	_, err := azkv.NewProviderE("https://example.com/not-a-key")
	if err == nil {
		t.Fatal("expected error for malformed URL")
	}
}

// TestKeyGroupsShape verifies KeyGroups produces a single group with
// one master key per URL.
func TestKeyGroupsShape(t *testing.T) {
	t.Parallel()
	kp := azkv.NewProvider(testURL1, testURL2)
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
