package cipher

import (
	"context"
	"errors"
	"testing"

	"github.com/getsops/sops/v3"
)

// TestStaticKeyProvider verifies StaticKeyProvider returns the supplied
// groups unmodified.
func TestStaticKeyProvider(t *testing.T) {
	t.Parallel()
	want := []sops.KeyGroup{{}, {}}
	kp := StaticKeyProvider(want...)
	got, err := kp.KeyGroups(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d", len(got), len(want))
	}
}

// TestKeyProviderFunc verifies that a plain function satisfies KeyProvider.
func TestKeyProviderFunc(t *testing.T) {
	t.Parallel()
	want := []sops.KeyGroup{{}}
	var kp KeyProvider = KeyProviderFunc(
		func(context.Context) ([]sops.KeyGroup, error) { return want, nil },
	)
	got, err := kp.KeyGroups(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d", len(got), len(want))
	}
}

// TestChainKeyProviders verifies group concatenation and error propagation.
func TestChainKeyProviders(t *testing.T) {
	t.Parallel()
	g1 := sops.KeyGroup{}
	g2 := sops.KeyGroup{}
	a := StaticKeyProvider(g1)
	b := StaticKeyProvider(g2)
	chain := ChainKeyProviders(a, b)
	got, err := chain.KeyGroups(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}

	t.Run("error aborts chain", func(t *testing.T) {
		t.Parallel()
		boom := errors.New("boom")
		broken := KeyProviderFunc(
			func(context.Context) ([]sops.KeyGroup, error) { return nil, boom },
		)
		chain := ChainKeyProviders(a, broken, b)
		_, err := chain.KeyGroups(context.Background())
		if !errors.Is(err, boom) {
			t.Fatalf("err = %v, want errors.Is boom", err)
		}
	})
}
