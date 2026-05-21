package ciphertest_test

import (
	"context"
	"testing"

	"github.com/dcadolph/cipher"
	"github.com/dcadolph/cipher/ciphertest"
)

// TestNewProviderRoundTrip verifies the helper produces a working
// recipient / identity pair end-to-end.
func TestNewProviderRoundTrip(t *testing.T) {
	kp, _ := ciphertest.NewProvider(t)
	enc := cipher.NewEncoder(kp)
	dec := cipher.NewDecoder()
	ciphertest.AssertRoundTrip(
		t, context.Background(), enc, dec,
		"x.yaml", []byte("foo: bar\n"), "foo: bar",
	)
}

// TestAssertRoundTripMultipleSubstrings exercises the contains-list path.
func TestAssertRoundTripMultipleSubstrings(t *testing.T) {
	kp, _ := ciphertest.NewProvider(t)
	enc := cipher.NewEncoder(kp)
	dec := cipher.NewDecoder()
	ciphertest.AssertRoundTrip(
		t, context.Background(), enc, dec,
		"creds.json", []byte(`{"user":"alice","pass":"hunter2"}`),
		`"user"`, `"alice"`, `"pass"`, `"hunter2"`,
	)
}
