package pgp_test

import (
	"context"
	"testing"

	"github.com/dcadolph/cipher/pgp"
)

const (
	testFP1 = "85D77543B3D624B63CEA9E6DBC17301B491B3F21"
	testFP2 = "FBC7B9E2A4F9289AC0C1D4843D16CEE4A27381B4"
)

// TestNewProviderPanicsOnEmpty verifies that the factory rejects empty input.
func TestNewProviderPanicsOnEmpty(t *testing.T) {
	t.Parallel()
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on no fingerprints")
		}
	}()
	_ = pgp.NewProvider()
}

// TestKeyGroupsShape verifies KeyGroups produces a single group with
// one master key per fingerprint.
func TestKeyGroupsShape(t *testing.T) {
	t.Parallel()
	kp := pgp.NewProvider(testFP1, testFP2)
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
	kp := pgp.NewProviderFromCSV(testFP1 + "," + testFP2)
	groups, err := kp.KeyGroups(context.Background())
	if err != nil {
		t.Fatalf("KeyGroups: %v", err)
	}
	if len(groups[0]) != 2 {
		t.Fatalf("group size = %d, want 2", len(groups[0]))
	}
}
