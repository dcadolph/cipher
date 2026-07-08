// Command cipher is the CLI front-end for the github.com/dcadolph/cipher
// library. It exposes encrypt, decrypt, edit, rotate, walk, and
// recipient-management verbs that the library supports.
package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// version is the CLI version string. Set via -ldflags during build.
var version = "dev"

// rootCmd is the cobra root for the cipher CLI.
var rootCmd = &cobra.Command{
	Use:   "cipher",
	Short: "Programmatic sops encryption, decryption, and rotation",
	Long: "cipher wraps the getsops/sops Go library with first-class\n" +
		"encryption, key rotation, recipient management, directory walks,\n" +
		".sops.yaml routing, and a git pre-commit safety check.",
}

func init() {
	rootCmd.AddCommand(
		newEncryptCmd(),
		newDecryptCmd(),
		newEditCmd(),
		newExecEnvCmd(),
		newExecFileCmd(),
		newRotateCmd(),
		newWalkCmd(),
		newAddRecipientCmd(),
		newRemoveRecipientCmd(),
		newRecipientsCmd(),
		newConfigCmd(),
		newPrecommitCmd(),
		newInfoCmd(),
		newFixCmd(),
		newDemoCmd(),
		newVersionCmd(),
	)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		var ee *exitError
		if errors.As(err, &ee) {
			if ee.err != nil {
				fmt.Fprintln(os.Stderr, "error:", ee.err)
			}
			os.Exit(ee.code)
		}
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// exitError carries an explicit process exit code up to main. It is
// used by the exec verbs to propagate a child process exit code. When
// err is nil the child already reported its own failure, so main exits
// with code and prints nothing.
type exitError struct {
	// err is an optional message printed to stderr before exit.
	err error
	// code is the process exit code to return.
	code int
}

// Error reports the exit code, and the wrapped message when present.
func (e *exitError) Error() string {
	if e.err != nil {
		return e.err.Error()
	}
	return fmt.Sprintf("exit status %d", e.code)
}

// Unwrap returns the wrapped error for errors.Is and errors.As.
func (e *exitError) Unwrap() error { return e.err }

// newVersionCmd returns the `cipher version` subcommand.
func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the cipher version",
		Run: func(cmd *cobra.Command, _ []string) {
			fmt.Fprintln(cmd.OutOrStdout(), version)
		},
	}
}
