package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/dcadolph/cipher"
)

// newDecryptCmd returns the `cipher decrypt` subcommand. Decryption
// does not need recipient flags: sops resolves identities from the
// standard env-based locations.
func newDecryptCmd() *cobra.Command {
	var inPlace bool
	var output string
	cmd := &cobra.Command{
		Use:   "decrypt PATH",
		Short: "Decrypt a single sops-encrypted file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := args[0]
			data, err := readPathOrStdin(path)
			if err != nil {
				return err
			}
			dec := cipher.NewDecoder()
			plain, err := dec.Decode(cmd.Context(), path, data)
			if err != nil {
				return fmt.Errorf("decrypt %q: %w", path, err)
			}
			switch {
			case inPlace && path == "-":
				return fmt.Errorf("--in-place is incompatible with stdin (path \"-\")")
			case inPlace:
				return writePathOrStdout(path, plain)
			case output != "":
				return writePathOrStdout(output, plain)
			default:
				return writePathOrStdout("-", plain)
			}
		},
	}
	cmd.Flags().BoolVarP(&inPlace, "in-place", "i", false, "write plaintext back to PATH")
	cmd.Flags().StringVarP(&output, "output", "o", "", "write plaintext to this path")
	return cmd
}
