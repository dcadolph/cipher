package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	yaml "go.yaml.in/yaml/v3"

	"github.com/dcadolph/cipher"
)

// newExecEnvCmd returns the `cipher exec-env` subcommand. It decrypts
// PATH, loads the resulting key/value pairs into the environment, and
// runs COMMAND through /bin/sh with those variables added.
//
// Security model: the decrypted secrets are placed in the child
// process environment. On most systems a same-user process can read
// another process environment (for example through /proc on Linux). Do
// not use exec-env on hosts where the threat model includes co-tenant
// processes running as the same user.
func newExecEnvCmd() *cobra.Command {
	return &cobra.Command{
		Use:           "exec-env PATH COMMAND",
		Short:         "Decrypt PATH and run COMMAND with the secrets as environment variables",
		Args:          cobra.ExactArgs(2),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			path, command := args[0], args[1]
			data, err := readPathOrStdin(path)
			if err != nil {
				return err
			}
			plain, err := cipher.NewDecoder().Decode(cmd.Context(), path, data)
			if err != nil {
				return fmt.Errorf("decrypt %q: %w", path, err)
			}
			env, err := envPairsFromPlaintext(path, plain)
			if err != nil {
				return err
			}
			return runShell(cmd.Context(), command, env)
		},
	}
}

// newExecFileCmd returns the `cipher exec-file` subcommand. It decrypts
// PATH to a temp file and runs COMMAND through /bin/sh, replacing the
// first "{}" with the temp file path (or appending the path when no
// placeholder is present).
//
// Security model: the plaintext is written to a file with mode 0600 in
// a freshly-created temp directory with mode 0700, removed best-effort
// when COMMAND exits. Co-tenants with root access can read the file
// while COMMAND runs. Do not use exec-file on shared hosts where the
// threat model includes the host operator.
func newExecFileCmd() *cobra.Command {
	var filename string
	cmd := &cobra.Command{
		Use:           "exec-file PATH COMMAND",
		Short:         "Decrypt PATH to a temp file and run COMMAND with {} replaced by its path",
		Args:          cobra.ExactArgs(2),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			path, command := args[0], args[1]
			data, err := readPathOrStdin(path)
			if err != nil {
				return err
			}
			plain, err := cipher.NewDecoder().Decode(cmd.Context(), path, data)
			if err != nil {
				return fmt.Errorf("decrypt %q: %w", path, err)
			}
			dir, err := os.MkdirTemp("", "cipher-exec-")
			if err != nil {
				return fmt.Errorf("temp dir: %w", err)
			}
			defer func() { _ = os.RemoveAll(dir) }()

			tmpPath := filepath.Join(dir, tempFileName(filename, path))
			if err := os.WriteFile(tmpPath, plain, 0o600); err != nil {
				return fmt.Errorf("write tmp: %w", err)
			}
			return runShell(cmd.Context(), substituteFile(command, tmpPath), nil)
		},
	}
	cmd.Flags().StringVar(&filename, "filename", "",
		"name for the decrypted temp file (default: base name of PATH)")
	return cmd
}

// runShell runs command through /bin/sh with extraEnv appended to the
// current environment. A non-zero child exit is returned as an
// exitError so the CLI exits with the child code and no extra message.
func runShell(ctx context.Context, command string, extraEnv []string) error {
	c := exec.CommandContext(ctx, "sh", "-c", command)
	c.Env = append(os.Environ(), extraEnv...)
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := c.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return &exitError{code: ee.ExitCode()}
		}
		return fmt.Errorf("exec: %w", err)
	}
	return nil
}

// substituteFile replaces every "{}" in command with the shell-quoted
// path. When command has no placeholder, the quoted path is appended.
func substituteFile(command, path string) string {
	quoted := shellQuote(path)
	if strings.Contains(command, "{}") {
		return strings.ReplaceAll(command, "{}", quoted)
	}
	return command + " " + quoted
}

// tempFileName picks the base name for the decrypted temp file. The
// explicit override wins; otherwise the base name of path is used, with
// a fallback when path is stdin or otherwise unusable.
func tempFileName(override, path string) string {
	name := override
	if name == "" {
		name = filepath.Base(path)
	}
	switch name {
	case "", ".", "-", "/":
		return "secret"
	default:
		return name
	}
}

// envPairsFromPlaintext converts decrypted file contents into KEY=VALUE
// environment pairs. Dotenv, YAML, and JSON are supported; the format
// is inferred from path. YAML and JSON must hold a flat map of scalar
// values.
func envPairsFromPlaintext(path string, plain []byte) ([]string, error) {
	switch cipher.FormatForPath(path) {
	case cipher.FormatDotenv:
		return parseDotenv(plain), nil
	case cipher.FormatJSON:
		return flattenScalarMap(plain, true)
	case cipher.FormatYAML:
		return flattenScalarMap(plain, false)
	default:
		return nil, fmt.Errorf(
			"exec-env: unsupported format for %q: need a .env, .yaml, or .json path", path)
	}
}

// parseDotenv splits dotenv content into KEY=VALUE pairs, skipping
// blank lines and comments. File order is preserved.
func parseDotenv(plain []byte) []string {
	var out []string
	for _, line := range strings.Split(string(plain), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		key, value, ok := strings.Cut(trimmed, "=")
		if !ok {
			continue
		}
		out = append(out, strings.TrimSpace(key)+"="+value)
	}
	return out
}

// flattenScalarMap parses a flat map of scalars into sorted KEY=VALUE
// pairs. Non-scalar values return an error naming the offending key.
func flattenScalarMap(plain []byte, isJSON bool) ([]string, error) {
	values := map[string]any{}
	if isJSON {
		if err := json.Unmarshal(plain, &values); err != nil {
			return nil, fmt.Errorf("parse json: %w", err)
		}
	} else if err := yaml.Unmarshal(plain, &values); err != nil {
		return nil, fmt.Errorf("parse yaml: %w", err)
	}

	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	out := make([]string, 0, len(keys))
	for _, key := range keys {
		scalar, ok := scalarString(values[key])
		if !ok {
			return nil, fmt.Errorf("exec-env: key %q is not a scalar", key)
		}
		out = append(out, key+"="+scalar)
	}
	return out, nil
}

// scalarString renders a scalar value as a string. The second return is
// false when the value is a map, slice, or other non-scalar.
func scalarString(value any) (string, bool) {
	switch typed := value.(type) {
	case nil:
		return "", true
	case string:
		return typed, true
	case bool:
		return strconv.FormatBool(typed), true
	case int:
		return strconv.Itoa(typed), true
	case int64:
		return strconv.FormatInt(typed, 10), true
	case float64:
		return strconv.FormatFloat(typed, 'g', -1, 64), true
	default:
		return "", false
	}
}
