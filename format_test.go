package cipher

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// TestFormatForPath verifies that FormatForPath maps file extensions to
// the expected Format value.
func TestFormatForPath(t *testing.T) {
	t.Parallel()
	tests := []struct {
		In   string
		Want Format
	}{
		// Test 0: YAML by .yaml extension.
		{In: "secrets.yaml", Want: FormatYAML},
		// Test 1: YAML by .yml extension.
		{In: "/etc/conf.yml", Want: FormatYAML},
		// Test 2: JSON by extension.
		{In: "creds.json", Want: FormatJSON},
		// Test 3: INI by extension.
		{In: "app.ini", Want: FormatIni},
		// Test 4: Dotenv by extension.
		{In: "vars.env", Want: FormatDotenv},
		// Test 5: Unknown extension falls back to binary.
		{In: "data.bin", Want: FormatBinary},
		// Test 6: No extension falls back to binary.
		{In: "data", Want: FormatBinary},
	}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			got := FormatForPath(test.In)
			if diff := cmp.Diff(test.Want, got); diff != "" {
				t.Errorf("mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestFormatFromString verifies the string-to-Format mapping.
func TestFormatFromString(t *testing.T) {
	t.Parallel()
	tests := []struct {
		In   string
		Want Format
	}{
		// Test 0: yaml.
		{In: "yaml", Want: FormatYAML},
		// Test 1: json.
		{In: "json", Want: FormatJSON},
		// Test 2: ini.
		{In: "ini", Want: FormatIni},
		// Test 3: dotenv.
		{In: "dotenv", Want: FormatDotenv},
		// Test 4: binary.
		{In: "binary", Want: FormatBinary},
		// Test 5: unknown falls back to binary.
		{In: "xml", Want: FormatBinary},
	}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			got := FormatFromString(test.In)
			if diff := cmp.Diff(test.Want, got); diff != "" {
				t.Errorf("mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestFormatName verifies the Format-to-string mapping.
func TestFormatName(t *testing.T) {
	t.Parallel()
	tests := []struct {
		In   Format
		Want string
	}{
		// Test 0: YAML.
		{In: FormatYAML, Want: "yaml"},
		// Test 1: JSON.
		{In: FormatJSON, Want: "json"},
		// Test 2: INI.
		{In: FormatIni, Want: "ini"},
		// Test 3: Dotenv.
		{In: FormatDotenv, Want: "dotenv"},
		// Test 4: Binary.
		{In: FormatBinary, Want: "binary"},
	}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			got := FormatName(test.In)
			if diff := cmp.Diff(test.Want, got); diff != "" {
				t.Errorf("mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
