package main

import (
	"bytes"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/dcadolph/cipher"
)

// TestParseDurationWithDays covers the day suffix branch, the plain
// time.ParseDuration branch, and the bad input branch.
func TestParseDurationWithDays(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Name    string
		In      string
		Want    time.Duration
		WantErr bool
	}{
		// Test 0: 90d resolves to 90 days.
		{Name: "90d", In: "90d", Want: 90 * 24 * time.Hour},
		// Test 1: bare hours pass through.
		{Name: "12h", In: "12h", Want: 12 * time.Hour},
		// Test 2: minutes pass through.
		{Name: "30m", In: "30m", Want: 30 * time.Minute},
		// Test 3: garbage day prefix surfaces an error.
		{Name: "abc-d", In: "abcd", WantErr: true},
		// Test 4: empty input is an error.
		{Name: "empty", In: "", WantErr: true},
	}
	for testNum, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			got, err := parseDurationWithDays(test.In)
			if (err != nil) != test.WantErr {
				t.Fatalf("Test %d (%s): err = %v, wantErr = %v",
					testNum, test.Name, err, test.WantErr)
			}
			if test.WantErr {
				return
			}
			if got != test.Want {
				t.Errorf("Test %d (%s): got = %v, want = %v",
					testNum, test.Name, got, test.Want)
			}
		})
	}
}

// TestFlattenRecipientSet checks that a cipher.Info with two groups
// of recipients flattens into the expected "<type>:<id>" string set.
func TestFlattenRecipientSet(t *testing.T) {
	t.Parallel()
	info := &cipher.Info{
		Groups: [][]cipher.RecipientInfo{
			{
				{Type: "age", Identifier: "age1alice"},
				{Type: "age", Identifier: "age1bob"},
			},
			{
				{Type: "kms", Identifier: "arn:aws:kms:...:key/abc"},
			},
		},
	}
	got := flattenRecipientSet(info)
	want := map[string]struct{}{
		"age:age1alice":               {},
		"age:age1bob":                 {},
		"kms:arn:aws:kms:...:key/abc": {},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("mismatch (-want +got):\n%s", diff)
	}
}

// TestSortedDiff covers identical sets, disjoint sets, and partial
// overlap. Output must be deterministic so reports are stable.
func TestSortedDiff(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Name string
		A, B map[string]struct{}
		Want []string
	}{
		{
			Name: "identical",
			A:    map[string]struct{}{"a": {}, "b": {}},
			B:    map[string]struct{}{"a": {}, "b": {}},
			Want: nil,
		},
		{
			Name: "disjoint",
			A:    map[string]struct{}{"a": {}, "b": {}},
			B:    map[string]struct{}{"c": {}},
			Want: []string{"a", "b"},
		},
		{
			Name: "partial",
			A:    map[string]struct{}{"x": {}, "y": {}, "z": {}},
			B:    map[string]struct{}{"y": {}},
			Want: []string{"x", "z"},
		},
	}
	for testNum, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			got := sortedDiff(test.A, test.B)
			if diff := cmp.Diff(test.Want, got); diff != "" {
				t.Errorf("Test %d (%s) mismatch (-want +got):\n%s",
					testNum, test.Name, diff)
			}
		})
	}
}

// TestEmitReports verifies the JSON encoder, including the pretty
// branch which sets indentation.
func TestEmitReports(t *testing.T) {
	t.Parallel()
	reports := []recipientReport{
		{Path: "a.yaml", Removed: []string{"age1bob"}},
	}

	var compact bytes.Buffer
	if err := emitReports(&compact, reports, false); err != nil {
		t.Fatalf("compact emit: %v", err)
	}
	if !bytes.Contains(compact.Bytes(), []byte(`"path":"a.yaml"`)) {
		t.Errorf("compact missing path field: %s", compact.String())
	}

	var pretty bytes.Buffer
	if err := emitReports(&pretty, reports, true); err != nil {
		t.Fatalf("pretty emit: %v", err)
	}
	if !bytes.Contains(pretty.Bytes(), []byte("  ")) {
		t.Errorf("pretty missing indentation: %s", pretty.String())
	}
}
