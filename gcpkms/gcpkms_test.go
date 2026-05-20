package gcpkms_test

import (
	"context"
	"testing"

	"github.com/dcadolph/cipher/gcpkms"
)

const (
	testID1 = "projects/p/locations/global/keyRings/r/cryptoKeys/a"
	testID2 = "projects/p/locations/global/keyRings/r/cryptoKeys/b"
)

// TestNewProviderPanicsOnEmpty verifies that the factory rejects empty input.
func TestNewProviderPanicsOnEmpty(t *testing.T) {
	t.Parallel()
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on no resource IDs")
		}
	}()
	_ = gcpkms.NewProvider()
}

// TestKeyGroupsShape verifies KeyGroups produces a single group with
// one master key per resource ID.
func TestKeyGroupsShape(t *testing.T) {
	t.Parallel()
	kp := gcpkms.NewProvider(testID1, testID2)
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
	kp := gcpkms.NewProviderFromCSV(testID1 + ", " + testID2)
	groups, err := kp.KeyGroups(context.Background())
	if err != nil {
		t.Fatalf("KeyGroups: %v", err)
	}
	if len(groups[0]) != 2 {
		t.Fatalf("group size = %d, want 2", len(groups[0]))
	}
}
