// Command cipher is the CLI front-end for the github.com/dcadolph/cipher
// library. It exposes encrypt, decrypt, edit, rotate, walk, and
// recipient-management verbs that the library supports.
package main

import (
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
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

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
