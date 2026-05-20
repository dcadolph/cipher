package cipher

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"

	"github.com/spf13/afero"

	"github.com/dcadolph/cipher/internal/atomic"
	"github.com/dcadolph/cipher/internal/sopsx"
)

// EditOptions tunes Edit behavior.
type EditOptions struct {
	// BackupSuffix, when non-empty, copies the encrypted original to
	// <path><suffix> before overwriting it. The backup is retained
	// after success so callers can revert or diff.
	BackupSuffix string
}

// Edit reads path from files, decrypts the contents with dec, invokes
// fn on the plaintext, re-encrypts the result with enc, and writes it
// back to the same path atomically.
//
// If fn returns the same bytes (by value), no write occurs and Edit
// returns nil. If fn returns an error, the file is left untouched and
// that error is returned wrapped.
//
// Atomicity: the encrypted bytes are written to a sibling temp file
// which is then renamed into place. On any failure the destination
// remains as it was before the call.
func Edit(
	ctx context.Context, files afero.Fs, path string,
	enc Encoder, dec Decoder,
	fn func(plaintext []byte) ([]byte, error),
) error {
	return EditWith(ctx, files, path, enc, dec, fn, EditOptions{})
}

// EditWith is Edit with explicit options.
func EditWith(
	ctx context.Context, files afero.Fs, path string,
	enc Encoder, dec Decoder,
	fn func(plaintext []byte) ([]byte, error),
	opts EditOptions,
) error {
	if files == nil {
		panic("cipher: EditWith: filesystem required")
	}
	if enc == nil {
		panic("cipher: EditWith: encoder required")
	}
	if dec == nil {
		panic("cipher: EditWith: decoder required")
	}
	if fn == nil {
		panic("cipher: EditWith: edit function required")
	}

	info, err := files.Stat(path)
	if err != nil {
		return fmt.Errorf("cipher: stat %q: %w", path, err)
	}
	original, err := afero.ReadFile(files, path)
	if err != nil {
		return fmt.Errorf("cipher: read %q: %w", path, err)
	}

	plaintext, err := dec.Decode(ctx, path, original)
	if err != nil {
		return fmt.Errorf("cipher: decode %q: %w", path, err)
	}

	modified, err := fn(plaintext)
	if err != nil {
		return fmt.Errorf("cipher: edit %q: %w", path, err)
	}
	if bytes.Equal(plaintext, modified) {
		return nil
	}

	encrypted, err := enc.Encode(ctx, path, modified)
	if err != nil {
		return fmt.Errorf("cipher: encode %q: %w", path, err)
	}
	if err := writeBackup(files, path, original, info, opts.BackupSuffix); err != nil {
		return err
	}
	if err := atomic.WriteFile(files, path, encrypted, info.Mode().Perm()); err != nil {
		return err
	}
	return nil
}

// Rotate decrypts data with dec and re-encrypts it with enc. A fresh
// data key is generated, so any compromise of the previous data key
// no longer protects the file. Recipients are reset to whatever enc's
// KeyProvider yields; pass the original Encoder to keep recipients,
// or a different one to switch backends.
func Rotate(
	ctx context.Context, path string, data []byte,
	enc Encoder, dec Decoder,
) ([]byte, error) {
	if enc == nil {
		panic("cipher: Rotate: encoder required")
	}
	if dec == nil {
		panic("cipher: Rotate: decoder required")
	}
	plain, err := dec.Decode(ctx, path, data)
	if err != nil {
		return nil, fmt.Errorf("cipher: rotate %q: %w", path, err)
	}
	out, err := enc.Encode(ctx, path, plain)
	if err != nil {
		return nil, fmt.Errorf("cipher: rotate %q: %w", path, err)
	}
	return out, nil
}

// RotateWalk applies Rotate to every matching file under root. Files
// that are not encrypted are skipped. Plain files do not cause failure.
func RotateWalk(
	ctx context.Context, files afero.Fs, root string,
	enc Encoder, dec Decoder, matchers []FileMatcher,
) error {
	return RotateWalkWith(ctx, files, root, enc, dec, matchers, WalkOptions{})
}

// RotateWalkWith is RotateWalk with explicit options.
func RotateWalkWith(
	ctx context.Context, files afero.Fs, root string,
	enc Encoder, dec Decoder, matchers []FileMatcher, opts WalkOptions,
) error {
	if files == nil {
		panic("cipher: RotateWalkWith: filesystem required")
	}
	if enc == nil {
		panic("cipher: RotateWalkWith: encoder required")
	}
	if dec == nil {
		panic("cipher: RotateWalkWith: decoder required")
	}
	return runWalk(ctx, files, root, matchers, opts,
		func(ctx context.Context, fs afero.Fs, path string, info fs.FileInfo) error {
			data, err := afero.ReadFile(fs, path)
			if err != nil {
				return fmt.Errorf("cipher: read %q: %w", path, err)
			}
			out, err := Rotate(ctx, path, data, enc, dec)
			switch {
			case errors.Is(err, ErrNotEncrypted):
				notify(opts.OnSkip, path, ErrNotEncrypted)
				return nil
			case err != nil:
				return err
			}
			if err := writeBackup(fs, path, data, info, opts.BackupSuffix); err != nil {
				return err
			}
			if err := atomic.WriteFile(fs, path, out, info.Mode().Perm()); err != nil {
				return err
			}
			notify(opts.OnFile, path, len(out))
			return nil
		})
}

// AddRecipient appends the keys from add to the file's key groups (as
// a new group) and re-wraps the data key for all recipients. The
// payload ciphertext is unchanged. The caller must hold an identity
// for at least one existing recipient so the data key can be unwrapped.
func AddRecipient(
	ctx context.Context, path string, data []byte,
	add KeyProvider, opts DecoderOptions,
) ([]byte, error) {
	if add == nil {
		panic("cipher: AddRecipient: KeyProvider required")
	}
	groups, err := add.KeyGroups(ctx)
	if err != nil {
		return nil, fmt.Errorf("cipher: AddRecipient: key groups: %w", err)
	}
	out, err := sopsx.AddRecipient(sopsx.AddRecipientInput{
		Path:            path,
		Data:            data,
		Format:          opts.Format,
		NewGroups:       groups,
		KeyServices:     opts.KeyServices,
		DecryptionOrder: opts.DecryptionOrder,
	})
	switch {
	case errors.Is(err, sopsx.ErrNotEncrypted):
		return nil, ErrNotEncrypted
	case err != nil:
		return nil, fmt.Errorf("cipher: AddRecipient: %w", err)
	}
	return out, nil
}

// RemoveRecipient drops master keys from the file's key groups whose
// ToString() identifier matches an entry in identifiers. The payload
// is not decrypted; this is a metadata-only edit.
func RemoveRecipient(
	ctx context.Context, path string, data []byte,
	identifiers ...string,
) ([]byte, error) {
	if len(identifiers) == 0 {
		return nil, fmt.Errorf("cipher: RemoveRecipient: at least one identifier required")
	}
	out, err := sopsx.RemoveRecipient(sopsx.RemoveRecipientInput{
		Path:            path,
		Data:            data,
		Identifiers:     identifiers,
		DropEmptyGroups: true,
	})
	switch {
	case errors.Is(err, sopsx.ErrNotEncrypted):
		return nil, ErrNotEncrypted
	case err != nil:
		return nil, fmt.Errorf("cipher: RemoveRecipient: %w", err)
	}
	return out, nil
}
