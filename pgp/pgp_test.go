package pgp_test

import (
	"context"
	"strings"
	"testing"

	"github.com/dcadolph/cipher/pgp"
)

const (
	testFP1 = "85D77543B3D624B63CEA9E6DBC17301B491B3F21"
	testFP2 = "FBC7B9E2A4F9289AC0C1D4843D16CEE4A27381B4"
)

// TestNewProviderRejectsEmpty verifies that NewProvider returns an
// error on empty input.
func TestNewProviderRejectsEmpty(t *testing.T) {
	t.Parallel()
	if _, err := pgp.NewProvider(); err == nil {
		t.Fatal("err = nil, want at-least-one-fingerprint error")
	}
}

// TestMustNewProviderPanicsOnEmpty verifies the Must helper panics
// where NewProvider would return an error.
func TestMustNewProviderPanicsOnEmpty(t *testing.T) {
	t.Parallel()
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on no fingerprints")
		}
	}()
	_ = pgp.MustNewProvider()
}

// TestKeyGroupsShape verifies KeyGroups produces a single group with
// one master key per fingerprint.
func TestKeyGroupsShape(t *testing.T) {
	t.Parallel()
	kp := pgp.MustNewProvider(testFP1, testFP2)
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

// TestNormalizeFingerprintCanonicalizesCase verifies that the same
// fingerprint in lower and upper case produces an identical master key
// identifier so callers cannot accidentally create distinct providers
// for the same key by varying hex case.
func TestNormalizeFingerprintCanonicalizesCase(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	lowerGroups, err := pgp.MustNewProvider(strings.ToLower(testFP1)).KeyGroups(ctx)
	if err != nil {
		t.Fatalf("lower KeyGroups: %v", err)
	}
	upperGroups, err := pgp.MustNewProvider(strings.ToUpper(testFP1)).KeyGroups(ctx)
	if err != nil {
		t.Fatalf("upper KeyGroups: %v", err)
	}
	lowerID := lowerGroups[0][0].ToString()
	upperID := upperGroups[0][0].ToString()
	if lowerID != upperID {
		t.Errorf("identifier mismatch:\n  lower input: %s\n  upper input: %s", lowerID, upperID)
	}
}

// TestNewProviderValidatesFingerprints exercises the validating
// constructor for accepted and rejected inputs.
func TestNewProviderValidatesFingerprints(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Name string
		In   []string
		Want bool
	}{
		// Test 0: Well-formed fingerprint.
		{Name: "valid", In: []string{testFP1}, Want: false},
		// Test 1: Empty input.
		{Name: "empty", In: nil, Want: true},
		// Test 2: Too short.
		{Name: "short", In: []string{"DEAD"}, Want: true},
		// Test 3: Non-hex.
		{Name: "non-hex", In: []string{
			"ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ",
		}, Want: true},
		// Test 4: 0x prefix accepted and normalized.
		{Name: "0x-prefix", In: []string{"0x" + testFP2}, Want: false},
	}
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			_, err := pgp.NewProvider(test.In...)
			if (err != nil) != test.Want {
				t.Errorf("err = %v, wantErr = %v", err, test.Want)
			}
		})
	}
}
