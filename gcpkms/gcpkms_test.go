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

// TestNewProviderRejectsEmpty verifies that NewProvider returns an
// error on empty input.
func TestNewProviderRejectsEmpty(t *testing.T) {
	t.Parallel()
	if _, err := gcpkms.NewProvider(); err == nil {
		t.Fatal("err = nil, want at-least-one-ID error")
	}
}

// TestMustNewProviderPanicsOnEmpty verifies the Must helper panics
// where NewProvider would return an error.
func TestMustNewProviderPanicsOnEmpty(t *testing.T) {
	t.Parallel()
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on no resource IDs")
		}
	}()
	_ = gcpkms.MustNewProvider()
}

// TestKeyGroupsShape verifies KeyGroups produces a single group with
// one master key per resource ID.
func TestKeyGroupsShape(t *testing.T) {
	t.Parallel()
	kp := gcpkms.MustNewProvider(testID1, testID2)
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

// TestNewProviderValidatesResourceID exercises the validating
// constructor for accepted and rejected inputs.
func TestNewProviderValidatesResourceID(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Name string
		In   string
		Want bool
	}{
		// Test 0: Standard resource ID.
		{Name: "standard", In: testID1, Want: false},
		// Test 1: With cryptoKeyVersions suffix.
		{Name: "versioned", In: testID1 + "/cryptoKeyVersions/1", Want: false},
		// Test 2: Wrong top-level label.
		{Name: "wrong-top", In: "project/p/locations/global/keyRings/r/cryptoKeys/k", Want: true},
		// Test 3: Too few segments.
		{Name: "short", In: "projects/p/locations/global", Want: true},
		// Test 4: Empty key name.
		{Name: "empty-name", In: "projects/p/locations/global/keyRings/r/cryptoKeys/", Want: true},
		// Test 5: Garbage.
		{Name: "garbage", In: "not-a-resource", Want: true},
	}
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			_, err := gcpkms.NewProvider(test.In)
			if (err != nil) != test.Want {
				t.Errorf("err = %v, wantErr = %v", err, test.Want)
			}
		})
	}
}
