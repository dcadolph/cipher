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

// TestNewProviderRejectsEmpty verifies that NewProvider returns an
// error on empty input.
func TestNewProviderRejectsEmpty(t *testing.T) {
	t.Parallel()
	if _, err := azkv.NewProvider(); err == nil {
		t.Fatal("err = nil, want at-least-one-URL error")
	}
}

// TestMustNewProviderPanicsOnEmpty verifies the Must helper panics
// where NewProvider would return an error.
func TestMustNewProviderPanicsOnEmpty(t *testing.T) {
	t.Parallel()
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on no URLs")
		}
	}()
	_ = azkv.MustNewProvider()
}

// TestNewProviderRejectsMalformed verifies URL parsing errors surface.
func TestNewProviderRejectsMalformed(t *testing.T) {
	t.Parallel()
	if _, err := azkv.NewProvider("https://example.com/not-a-key"); err == nil {
		t.Fatal("expected error for malformed URL")
	}
}

// TestKeyGroupsShape verifies KeyGroups produces a single group with
// one master key per URL.
func TestKeyGroupsShape(t *testing.T) {
	t.Parallel()
	kp := azkv.MustNewProvider(testURL1, testURL2)
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
