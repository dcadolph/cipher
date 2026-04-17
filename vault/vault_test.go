package vault_test

import (
	"context"
	"testing"

	"github.com/dcadolph/cipher/vault"
)

const (
	testURI1 = "http://127.0.0.1:8200/v1/transit/keys/firstkey"
	testURI2 = "http://127.0.0.1:8200/v1/transit/keys/secondkey"
)

// TestNewProviderRejectsEmpty verifies that NewProvider returns an
// error on empty input.
func TestNewProviderRejectsEmpty(t *testing.T) {
	t.Parallel()
	if _, err := vault.NewProvider(); err == nil {
		t.Fatal("err = nil, want at-least-one-URI error")
	}
}

// TestMustNewProviderPanicsOnEmpty verifies the Must helper panics
// where NewProvider would return an error.
func TestMustNewProviderPanicsOnEmpty(t *testing.T) {
	t.Parallel()
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on no URIs")
		}
	}()
	_ = vault.MustNewProvider()
}

// TestNewProviderRejectsMalformed verifies URI parsing errors surface.
func TestNewProviderRejectsMalformed(t *testing.T) {
	t.Parallel()
	if _, err := vault.NewProvider("not a uri at all"); err == nil {
		t.Fatal("expected error for malformed URI")
	}
}

// TestKeyGroupsShape verifies KeyGroups produces a single group with
// one master key per URI.
func TestKeyGroupsShape(t *testing.T) {
	t.Parallel()
	kp := vault.MustNewProvider(testURI1, testURI2)
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
