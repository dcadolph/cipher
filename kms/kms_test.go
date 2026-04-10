package kms_test

import (
	"context"
	"testing"

	"github.com/dcadolph/cipher/kms"
)

const (
	testARN1 = "arn:aws:kms:us-east-1:111111111111:key/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	testARN2 = "arn:aws:kms:us-east-1:111111111111:key/bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
)

// TestNewProviderRejectsEmpty verifies that NewProvider returns an
// error on empty or whitespace-only input.
func TestNewProviderRejectsEmpty(t *testing.T) {
	t.Parallel()
	t.Run("no args", func(t *testing.T) {
		t.Parallel()
		if _, err := kms.NewProvider(kms.ProviderOptions{}); err == nil {
			t.Fatal("err = nil, want at-least-one-ARN error")
		}
	})
	t.Run("only whitespace", func(t *testing.T) {
		t.Parallel()
		if _, err := kms.NewProvider(kms.ProviderOptions{}, " ", ""); err == nil {
			t.Fatal("err = nil, want at-least-one-ARN error")
		}
	})
}

// TestMustNewProviderPanicsOnEmpty verifies the Must-prefixed helper
// panics where NewProvider would return an error.
func TestMustNewProviderPanicsOnEmpty(t *testing.T) {
	t.Parallel()
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on no ARNs")
		}
	}()
	_ = kms.MustNewProvider(kms.ProviderOptions{})
}

// TestKeyGroupsShape verifies KeyGroups produces a single group with
// one master key per ARN.
func TestKeyGroupsShape(t *testing.T) {
	t.Parallel()
	kp := kms.MustNewProvider(kms.ProviderOptions{}, testARN1, testARN2)
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

// TestNewProviderWithOptions verifies that options thread through to
// each master key.
func TestNewProviderWithOptions(t *testing.T) {
	t.Parallel()
	opts := kms.ProviderOptions{
		EncryptionContext: map[string]string{"app": "test"},
		Profile:           "test-profile",
		Role:              "arn:aws:iam::111111111111:role/test-role",
	}
	kp := kms.MustNewProvider(opts, testARN1)
	groups, err := kp.KeyGroups(context.Background())
	if err != nil {
		t.Fatalf("KeyGroups: %v", err)
	}
	if len(groups[0]) != 1 {
		t.Fatalf("group size = %d, want 1", len(groups[0]))
	}
}

// TestNewProviderValidatesARN exercises the validating constructor for
// accepted and rejected inputs.
func TestNewProviderValidatesARN(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Name string
		In   string
		Want bool
	}{
		// Test 0: Standard key ARN.
		{Name: "key", In: testARN1, Want: false},
		// Test 1: Alias ARN.
		{Name: "alias", In: "arn:aws:kms:us-east-1:111111111111:alias/sops", Want: false},
		// Test 2: aws-cn partition.
		{Name: "aws-cn", In: "arn:aws-cn:kms:cn-north-1:111111111111:key/x", Want: false},
		// Test 3: Wrong service.
		{Name: "wrong-service", In: "arn:aws:s3:::bucket/key", Want: true},
		// Test 4: Missing region.
		{Name: "no-region", In: "arn:aws:kms::111111111111:key/x", Want: true},
		// Test 5: Bad resource shape.
		{Name: "bad-resource", In: "arn:aws:kms:us-east-1:111111111111:secret/x", Want: true},
		// Test 6: Not an ARN.
		{Name: "garbage", In: "hello", Want: true},
	}
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			_, err := kms.NewProvider(kms.ProviderOptions{}, test.In)
			if (err != nil) != test.Want {
				t.Errorf("err = %v, wantErr = %v", err, test.Want)
			}
		})
	}
}

// TestNewProviderRejectsBadRole verifies the role-ARN validation path.
func TestNewProviderRejectsBadRole(t *testing.T) {
	t.Parallel()
	_, err := kms.NewProvider(
		kms.ProviderOptions{Role: "arn:aws:iam::111111111111:user/test"},
		testARN1,
	)
	if err == nil {
		t.Fatal("err = nil, want bad-role error")
	}
}

// TestNewProviderValidatesEncryptionContext covers the
// EncryptionContext character and shape validation paths.
func TestNewProviderValidatesEncryptionContext(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Name string
		Ctx  map[string]string
		Want bool
	}{
		// Test 0: Empty map is OK.
		{Name: "empty", Ctx: nil, Want: false},
		// Test 1: Plain ASCII key/value is OK.
		{Name: "ascii", Ctx: map[string]string{"env": "prod"}, Want: false},
		// Test 2: Empty key.
		{Name: "empty-key", Ctx: map[string]string{"": "v"}, Want: true},
		// Test 3: Empty value.
		{Name: "empty-value", Ctx: map[string]string{"k": ""}, Want: true},
		// Test 4: Control character in key.
		{Name: "control-key", Ctx: map[string]string{"a\x01b": "v"}, Want: true},
		// Test 5: Control character in value.
		{Name: "control-value", Ctx: map[string]string{"k": "v\nw"}, Want: true},
	}
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			_, err := kms.NewProvider(
				kms.ProviderOptions{EncryptionContext: test.Ctx},
				testARN1,
			)
			if (err != nil) != test.Want {
				t.Errorf("err = %v, wantErr = %v", err, test.Want)
			}
		})
	}
}
