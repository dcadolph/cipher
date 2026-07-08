package main

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// TestParseExtractPath covers key and index steps, quote forms, spacing,
// and the malformed-expression error paths.
func TestParseExtractPath(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Name      string
		Expr      string
		WantSteps []extractStep
		WantErr   bool
	}{{ // Test 0: Two double-quoted keys.
		Name: "two keys", Expr: `["db"]["password"]`,
		WantSteps: []extractStep{{key: "db"}, {key: "password"}},
	}, { // Test 1: Key then index.
		Name: "key index", Expr: `["hosts"][0]`,
		WantSteps: []extractStep{{key: "hosts"}, {index: 0, isIndex: true}},
	}, { // Test 2: Single quotes and spacing between groups.
		Name: "single quote", Expr: `['a'] ['b']`,
		WantSteps: []extractStep{{key: "a"}, {key: "b"}},
	}, { // Test 3: Empty expression is an error.
		Name: "empty", Expr: "", WantErr: true,
	}, { // Test 4: Missing opening bracket.
		Name: "no bracket", Expr: `"a"`, WantErr: true,
	}, { // Test 5: Unterminated string.
		Name: "unterminated", Expr: `["a`, WantErr: true,
	}, { // Test 6: Non-numeric index.
		Name: "bad index", Expr: `[x]`, WantErr: true,
	}}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d %s", testNum, test.Name), func(t *testing.T) {
			t.Parallel()
			got, err := parseExtractPath(test.Expr)
			if test.WantErr {
				if err == nil {
					t.Fatalf("want error, got nil (steps %+v)", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if diff := cmp.Diff(test.WantSteps, got,
				cmp.AllowUnexported(extractStep{})); diff != "" {
				t.Errorf("steps mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestExtractValue covers scalar, nested, array, subtree, and error
// cases across YAML and JSON.
func TestExtractValue(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Name    string
		Path    string
		In      string
		Expr    string
		WantOut string
		WantErr bool
	}{{ // Test 0: Nested YAML scalar renders raw.
		Name: "yaml nested", Path: "s.yaml",
		In: "db:\n  password: super-secret\n", Expr: `["db"]["password"]`,
		WantOut: "super-secret",
	}, { // Test 1: Top-level JSON scalar.
		Name: "json scalar", Path: "s.json",
		In: `{"token":"abc123"}`, Expr: `["token"]`, WantOut: "abc123",
	}, { // Test 2: Array index into JSON.
		Name: "json index", Path: "s.json",
		In: `{"hosts":["a","b","c"]}`, Expr: `["hosts"][1]`, WantOut: "b",
	}, { // Test 3: Subtree re-encodes in YAML.
		Name: "yaml subtree", Path: "s.yaml",
		In: "db:\n  inner: value\n", Expr: `["db"]`, WantOut: "inner: value\n",
	}, { // Test 4: Missing key errors.
		Name: "missing key", Path: "s.yaml",
		In: "db:\n  password: x\n", Expr: `["nope"]`, WantErr: true,
	}, { // Test 5: Index out of range errors.
		Name: "index oob", Path: "s.json",
		In: `{"hosts":["a"]}`, Expr: `["hosts"][5]`, WantErr: true,
	}, { // Test 6: Unsupported format errors.
		Name: "unsupported", Path: "s.ini",
		In: "k=v", Expr: `["k"]`, WantErr: true,
	}}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d %s", testNum, test.Name), func(t *testing.T) {
			t.Parallel()
			got, err := extractValue(test.Path, []byte(test.In), test.Expr)
			if test.WantErr {
				if err == nil {
					t.Fatalf("want error, got nil (out %q)", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if diff := cmp.Diff(test.WantOut, string(got)); diff != "" {
				t.Errorf("output mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
