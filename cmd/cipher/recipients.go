package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/dcadolph/cipher"
)

// newAddRecipientCmd: `cipher add-recipient PATH`.
func newAddRecipientCmd() *cobra.Command {
	var inPlace bool
	var output string
	flags := &providerFlags{}
	cmd := &cobra.Command{
		Use:   "add-recipient PATH",
		Short: "Add recipients to an encrypted file without re-encrypting the payload",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := args[0]
			kp, err := flags.keyProvider()
			if err != nil {
				return err
			}
			data, err := readPathOrStdin(path)
			if err != nil {
				return err
			}
			out, err := cipher.AddRecipient(cmd.Context(), path, data, kp, cipher.DecoderOptions{})
			if err != nil {
				return fmt.Errorf("add-recipient %q: %w", path, err)
			}
			switch {
			case inPlace && path == "-":
				return fmt.Errorf("--in-place is incompatible with stdin")
			case inPlace:
				return writePathOrStdout(path, out)
			case output != "":
				return writePathOrStdout(output, out)
			default:
				return writePathOrStdout("-", out)
			}
		},
	}
	flags.bind(cmd.Flags())
	cmd.Flags().BoolVarP(&inPlace, "in-place", "i", false, "write back to PATH")
	cmd.Flags().StringVarP(&output, "output", "o", "", "write to this path")
	return cmd
}

// newRemoveRecipientCmd: `cipher remove-recipient PATH IDENTIFIER [IDENTIFIER...]`.
func newRemoveRecipientCmd() *cobra.Command {
	var inPlace bool
	var output string
	cmd := &cobra.Command{
		Use:   "remove-recipient PATH IDENTIFIER [IDENTIFIER...]",
		Short: "Remove recipients from an encrypted file without re-encrypting the payload",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := args[0]
			ids := args[1:]
			data, err := readPathOrStdin(path)
			if err != nil {
				return err
			}
			out, err := cipher.RemoveRecipient(cmd.Context(), path, data, ids...)
			if err != nil {
				return fmt.Errorf("remove-recipient %q: %w", path, err)
			}
			switch {
			case inPlace && path == "-":
				return fmt.Errorf("--in-place is incompatible with stdin")
			case inPlace:
				return writePathOrStdout(path, out)
			case output != "":
				return writePathOrStdout(output, out)
			default:
				return writePathOrStdout("-", out)
			}
		},
	}
	cmd.Flags().BoolVarP(&inPlace, "in-place", "i", false, "write back to PATH")
	cmd.Flags().StringVarP(&output, "output", "o", "", "write to this path")
	return cmd
}
