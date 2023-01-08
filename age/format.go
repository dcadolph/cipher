package age

import "go.mozilla.org/sops/v3/cmd/sops/formats"

type Format string

const (
	FmtYAML   = formats.Yaml
	FmtJSON   = formats.Json
	FmtINI    = formats.Ini
	FmtENV    = formats.Dotenv
	FmtBinary = formats.Binary
)
