package cipher

import "github.com/getsops/sops/v3/cmd/sops/formats"

// Format identifies a sops file format. It is a type alias for the
// underlying sops format type so callers can pass Format values
// directly to lower-level sops APIs without conversion.
type Format = formats.Format

// Format constants mirror the underlying sops formats.
const (
	FormatBinary = formats.Binary
	FormatDotenv = formats.Dotenv
	FormatIni    = formats.Ini
	FormatJSON   = formats.Json
	FormatYAML   = formats.Yaml
)

// FormatForPath returns the format associated with the file path,
// inferred from its extension. Unknown extensions resolve to FormatBinary.
func FormatForPath(path string) Format {
	return formats.FormatForPath(path)
}

// FormatFromString returns the Format for the given lowercase name
// ("yaml", "json", "ini", "dotenv", "binary"). Unknown names resolve
// to FormatBinary.
func FormatFromString(name string) Format {
	return formats.FormatFromString(name)
}

// FormatName returns the canonical string name for f.
func FormatName(f Format) string {
	switch f {
	case FormatYAML:
		return "yaml"
	case FormatJSON:
		return "json"
	case FormatIni:
		return "ini"
	case FormatDotenv:
		return "dotenv"
	case FormatBinary:
		return "binary"
	default:
		return "binary"
	}
}
