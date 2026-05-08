package util_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/dcadolph/cipher/internal/util"
)

// TestTrimEmpty exercises the trim-and-drop helper across whitespace,
// empty, and mixed inputs.
func TestTrimEmpty(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Name     string
		In       []string
		WantList []string
	}{
		// Test 0: Empty input.
		{Name: "nil", In: nil, WantList: []string{}},
		// Test 1: Pure empty strings.
		{Name: "all-empty", In: []string{"", "", ""}, WantList: []string{}},
		// Test 2: Pure whitespace strings.
		{Name: "all-whitespace", In: []string{" ", "\t", "\n"}, WantList: []string{}},
		// Test 3: Surrounding whitespace.
		{Name: "padded", In: []string{" arn1 ", "\tarn2\n"}, WantList: []string{"arn1", "arn2"}},
		// Test 4: Mixed empty and non-empty.
		{Name: "mixed", In: []string{"", " ", "arn1", "\t", "arn2", ""}, WantList: []string{"arn1", "arn2"}},
		// Test 5: Already trimmed input is preserved.
		{Name: "already-trimmed", In: []string{"a", "b", "c"}, WantList: []string{"a", "b", "c"}},
	}
	for testNum, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			got := util.TrimEmpty(test.In)
			if diff := cmp.Diff(test.WantList, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("test %d %s mismatch (-want +got):\n%s", testNum, test.Name, diff)
			}
		})
	}
}

// TestSplitCSV exercises the CSV split helper across empty, single,
// and multi-element inputs with assorted whitespace.
func TestSplitCSV(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Name     string
		In       string
		WantList []string
	}{
		// Test 0: Empty string.
		{Name: "empty", In: "", WantList: nil},
		// Test 1: Whitespace only.
		{Name: "whitespace", In: "  ", WantList: []string{}},
		// Test 2: Single value, no commas.
		{Name: "single", In: "arn:aws:kms:us-east-1:1:key/abc", WantList: []string{"arn:aws:kms:us-east-1:1:key/abc"}},
		// Test 3: Multiple values with padding.
		{Name: "multi-padded", In: " arn1 , arn2 ,arn3", WantList: []string{"arn1", "arn2", "arn3"}},
		// Test 4: Leading and trailing commas dropped.
		{Name: "leading-trailing-comma", In: ",arn1,arn2,", WantList: []string{"arn1", "arn2"}},
		// Test 5: Consecutive commas dropped.
		{Name: "double-comma", In: "arn1,,arn2", WantList: []string{"arn1", "arn2"}},
	}
	for testNum, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			got := util.SplitCSV(test.In)
			if diff := cmp.Diff(test.WantList, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("test %d %s mismatch (-want +got):\n%s", testNum, test.Name, diff)
			}
		})
	}
}
