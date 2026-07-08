package main

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

// TestEnvPairsFromPlaintext covers dotenv, YAML, and JSON flattening,
// plus the non-scalar and unsupported-format error paths.
func TestEnvPairsFromPlaintext(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Name    string
		Path    string
		In      string
		WantEnv []string
		WantErr bool
	}{{ // Test 0: Dotenv preserves file order and skips comments/blanks.
		Name:    "dotenv",
		Path:    "secrets.env",
		In:      "# comment\nDB_PASSWORD=super-secret\n\nAPI_KEY=abc=123\n",
		WantEnv: []string{"DB_PASSWORD=super-secret", "API_KEY=abc=123"},
	}, { // Test 1: YAML flat scalars sort by key.
		Name:    "yaml",
		Path:    "secrets.yaml",
		In:      "db_password: super-secret\nport: 5432\ntls: true\n",
		WantEnv: []string{"db_password=super-secret", "port=5432", "tls=true"},
	}, { // Test 2: JSON flat scalars sort by key.
		Name:    "json",
		Path:    "secrets.json",
		In:      `{"b_key":"two","a_key":"one"}`,
		WantEnv: []string{"a_key=one", "b_key=two"},
	}, { // Test 3: Nested YAML value is not a scalar.
		Name:    "yaml nested",
		Path:    "secrets.yaml",
		In:      "outer:\n  inner: value\n",
		WantErr: true,
	}, { // Test 4: Unknown extension is unsupported.
		Name:    "unsupported",
		Path:    "secrets.ini",
		In:      "k=v",
		WantErr: true,
	}}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d %s", testNum, test.Name), func(t *testing.T) {
			t.Parallel()
			got, err := envPairsFromPlaintext(test.Path, []byte(test.In))
			if test.WantErr {
				if err == nil {
					t.Fatalf("want error, got nil (env %v)", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if diff := cmp.Diff(test.WantEnv, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("env mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestSubstituteFile covers placeholder replacement and the append
// fallback when no placeholder is present.
func TestSubstituteFile(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Name    string
		Command string
		Path    string
		WantOut string
	}{{ // Test 0: Placeholder replaced with the quoted path.
		Name: "placeholder", Command: "cat {}", Path: "/tmp/x", WantOut: "cat '/tmp/x'",
	}, { // Test 1: Every placeholder replaced.
		Name: "repeated", Command: "diff {} {}", Path: "/a b", WantOut: "diff '/a b' '/a b'",
	}, { // Test 2: No placeholder appends the quoted path.
		Name: "append", Command: "cat", Path: "/tmp/x", WantOut: "cat '/tmp/x'",
	}}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d %s", testNum, test.Name), func(t *testing.T) {
			t.Parallel()
			got := substituteFile(test.Command, test.Path)
			if diff := cmp.Diff(test.WantOut, got); diff != "" {
				t.Errorf("mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestTempFileName covers the override, base-name, and fallback cases.
func TestTempFileName(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Name     string
		Override string
		Path     string
		WantName string
	}{{ // Test 0: Override wins.
		Name: "override", Override: "config.yaml", Path: "secrets.yaml", WantName: "config.yaml",
	}, { // Test 1: Base name of path.
		Name: "base", Override: "", Path: "dir/secrets.yaml", WantName: "secrets.yaml",
	}, { // Test 2: Stdin falls back to a safe default.
		Name: "stdin", Override: "", Path: "-", WantName: "secret",
	}}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d %s", testNum, test.Name), func(t *testing.T) {
			t.Parallel()
			got := tempFileName(test.Override, test.Path)
			if diff := cmp.Diff(test.WantName, got); diff != "" {
				t.Errorf("mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestRunShellExitCode confirms a zero exit returns nil and a non-zero
// exit propagates as an exitError carrying the child code.
func TestRunShellExitCode(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Name     string
		Command  string
		WantCode int
		WantErr  bool
	}{{ // Test 0: Success returns nil.
		Name: "success", Command: "true", WantErr: false,
	}, { // Test 1: Non-zero exit propagates the child code.
		Name: "exit 7", Command: "exit 7", WantErr: true, WantCode: 7,
	}, { // Test 2: Environment pair reaches the child.
		Name: "env visible", Command: `test "$CIPHER_TEST_VAR" = ok`, WantErr: false,
	}}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d %s", testNum, test.Name), func(t *testing.T) {
			t.Parallel()
			err := runShell(context.Background(), test.Command, []string{"CIPHER_TEST_VAR=ok"})
			if !test.WantErr {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			var ee *exitError
			if !errors.As(err, &ee) {
				t.Fatalf("want *exitError, got %T: %v", err, err)
			}
			if ee.code != test.WantCode {
				t.Errorf("exit code: want %d, got %d", test.WantCode, ee.code)
			}
		})
	}
}
