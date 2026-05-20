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

// TestNewProviderPanicsOnEmpty verifies that the factory rejects empty input.
func TestNewProviderPanicsOnEmpty(t *testing.T) {
	t.Parallel()
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on no URIs")
		}
	}()
	_ = vault.NewProvider()
}

// TestNewProviderEMalformed verifies the error-returning constructor surfaces
// URI parsing errors.
func TestNewProviderEMalformed(t *testing.T) {
	t.Parallel()
	_, err := vault.NewProviderE("not a uri at all")
	if err == nil {
		t.Fatal("expected error for malformed URI")
	}
}

// TestKeyGroupsShape verifies KeyGroups produces a single group with
// one master key per URI.
func TestKeyGroupsShape(t *testing.T) {
	t.Parallel()
	kp := vault.NewProvider(testURI1, testURI2)
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

// TestNewProviderFromCSV verifies parsing of a comma-separated list.
func TestNewProviderFromCSV(t *testing.T) {
	t.Parallel()
	kp := vault.NewProviderFromCSV(testURI1 + "," + testURI2)
	groups, err := kp.KeyGroups(context.Background())
	if err != nil {
		t.Fatalf("KeyGroups: %v", err)
	}
	if len(groups[0]) != 2 {
		t.Fatalf("group size = %d, want 2", len(groups[0]))
	}
}
