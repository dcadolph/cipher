package sopsconfig

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/dcadolph/cipher"
)

// TestMacModeFromBool covers both branches of the legacy bool to
// MACMode translation.
func TestMacModeFromBool(t *testing.T) {
	t.Parallel()
	tests := []struct {
		WantMode cipher.MACMode
		In       bool
	}{
		// Test 0: false maps to MAC over all leaves (sops default).
		{In: false, WantMode: cipher.MACOnAll},
		// Test 1: true maps to MAC over encrypted leaves only.
		{In: true, WantMode: cipher.MACOnEncrypted},
	}
	for testNum, test := range tests {
		t.Run("", func(t *testing.T) {
			t.Parallel()
			got := macModeFromBool(test.In)
			if diff := cmp.Diff(test.WantMode, got); diff != "" {
				t.Errorf("Test %d mismatch (-want +got):\n%s", testNum, diff)
			}
		})
	}
}

// TestToPtrMap covers the nil short circuit, the empty short circuit,
// and a populated map. Each output entry must point at the matching
// value rather than at a shared loop variable.
func TestToPtrMap(t *testing.T) {
	t.Parallel()
	t.Run("nil", func(t *testing.T) {
		t.Parallel()
		if toPtrMap(nil) != nil {
			t.Error("toPtrMap(nil) not nil")
		}
	})
	t.Run("empty", func(t *testing.T) {
		t.Parallel()
		if toPtrMap(map[string]string{}) != nil {
			t.Error("toPtrMap(empty) not nil")
		}
	})
	t.Run("populated", func(t *testing.T) {
		t.Parallel()
		in := map[string]string{"a": "1", "b": "2"}
		out := toPtrMap(in)
		if len(out) != len(in) {
			t.Fatalf("len = %d, want %d", len(out), len(in))
		}
		for k, want := range in {
			if out[k] == nil || *out[k] != want {
				t.Errorf("out[%q] = %v, want %q", k, out[k], want)
			}
		}
	})
}
