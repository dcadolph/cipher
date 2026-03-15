package cipher

import (
	"context"
	"errors"
	"fmt"

	"github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/keyservice"

	"github.com/dcadolph/cipher/internal/sopsx"
)

// Decoder decrypts a file's bytes for the given path.
type Decoder interface {
	// Decode returns the plaintext bytes for sops-encrypted data
	// identified by path. The path is used for format detection
	// unless the Decoder was configured with a fixed format.
	// Implementations should return ErrNotEncrypted when data does
	// not carry sops metadata.
	Decode(ctx context.Context, path string, data []byte) ([]byte, error)
}

// DecoderFunc adapts a plain function to Decoder.
type DecoderFunc func(ctx context.Context, path string, data []byte) ([]byte, error)

// Decode calls f.
func (f DecoderFunc) Decode(ctx context.Context, path string, data []byte) ([]byte, error) {
	return f(ctx, path, data)
}

// DecoderOptions tunes the behavior of a Decoder created with NewDecoderWith.
type DecoderOptions struct {
	// Format, when non-zero, fixes the format for every Decode call.
	// When zero, format is derived from the path on each call.
	Format Format
	// KeyServices overrides the default local key service. Empty means
	// a single local key service is used.
	KeyServices []keyservice.KeyServiceClient
	// DecryptionOrder controls which key types are tried first.
	// Empty means sops.DefaultDecryptionOrder.
	DecryptionOrder []string
	// IgnoreMAC, when true, skips message authentication verification.
	IgnoreMAC bool
	// Cipher overrides the default AES cipher. Nil means aes.NewCipher().
	Cipher sops.Cipher
	// Logger receives decode-time events. Nil uses NopLogger.
	Logger Logger
	// OnDecrypt is called after every successful Decode with the file
	// path, ciphertext size, and plaintext size. Nil is a no-op.
	OnDecrypt func(path string, ciphertextBytes, plaintextBytes int)
	// OnDecryptAudit is called after every successful Decode with the
	// file path, the full set of recipients recorded in the file's
	// metadata, and the error from the recipient-introspection step.
	// Use this for compliance audit trails when you need to log "this
	// file was decrypted and these identities are listed on it." The
	// specific MasterKey that performed the unwrap is not surfaced
	// because sops's public API does not expose it. The recipient set
	// is sufficient for most compliance regimes.
	//
	// When introspection fails (corrupt metadata, format mismatch),
	// recipients is empty and inspectErr is non-nil. The callback is
	// still invoked so audit code can record "decrypt occurred, but
	// the recipient list could not be read" instead of silently
	// missing the event.
	OnDecryptAudit func(path string, recipients []RecipientInfo, inspectErr error)
	// MaxCiphertextBytes is the maximum allowed ciphertext size in
	// bytes. Zero means no limit. Callers handling untrusted input
	// (HTTP request bodies, webhook payloads, etc.) should set this
	// to defend against pathological inputs that can balloon during
	// parsing. Returns ErrTooLarge if the input exceeds the limit.
	MaxCiphertextBytes int
}

// NewDecoder returns a Decoder backed by sops using sensible defaults:
// AES cipher, local key service, format inferred from each file's path,
// MAC verification enabled.
func NewDecoder() Decoder {
	return NewDecoderWith(DecoderOptions{})
}

// NewDecoderWith returns a Decoder backed by sops using the supplied options.
func NewDecoderWith(opts DecoderOptions) Decoder {
	log := opts.Logger
	if log == nil {
		log = NopLogger
	}
	return DecoderFunc(func(ctx context.Context, path string, data []byte) ([]byte, error) {
		log.Debugf("cipher.Decode start: path=%s bytes=%d", path, len(data))
		out, err := sopsx.Decrypt(sopsx.DecryptInput{
			Path:               path,
			Data:               data,
			Format:             opts.Format,
			KeyServices:        opts.KeyServices,
			DecryptionOrder:    opts.DecryptionOrder,
			IgnoreMAC:          opts.IgnoreMAC,
			Cipher:             opts.Cipher,
			MaxCiphertextBytes: opts.MaxCiphertextBytes,
		})
		switch {
		case errors.Is(err, sopsx.ErrNotEncrypted):
			log.Warnf("cipher.Decode skip not-encrypted: path=%s", path)
			return nil, ErrNotEncrypted
		case errors.Is(err, sopsx.ErrTooLarge):
			log.Warnf("cipher.Decode too large: path=%s bytes=%d limit=%d",
				path, len(data), opts.MaxCiphertextBytes)
			return nil, ErrTooLarge
		case err != nil:
			return nil, fmt.Errorf("%w: %w", ErrDecode, err)
		}
		log.Debugf("cipher.Decode done: path=%s ciphertext=%d plaintext=%d",
			path, len(data), len(out))
		if opts.OnDecrypt != nil {
			opts.OnDecrypt(path, len(data), len(out))
		}
		if opts.OnDecryptAudit != nil {
			info, infoErr := InspectPath(path, data)
			if infoErr != nil {
				log.Warnf("cipher.Decode audit introspection failed: path=%s err=%v", path, infoErr)
				opts.OnDecryptAudit(path, nil, infoErr)
			} else {
				var all []RecipientInfo
				for _, g := range info.Groups {
					all = append(all, g...)
				}
				opts.OnDecryptAudit(path, all, nil)
			}
		}
		return out, nil
	})
}

// ChainDecoders returns a Decoder that feeds the output of each Decoder
// into the next.
func ChainDecoders(first Decoder, rest ...Decoder) Decoder {
	if first == nil {
		panic("cipher: ChainDecoders: first decoder required")
	}
	return DecoderFunc(func(ctx context.Context, path string, data []byte) ([]byte, error) {
		out, err := first.Decode(ctx, path, data)
		if err != nil {
			return nil, err
		}
		for _, d := range rest {
			out, err = d.Decode(ctx, path, out)
			if err != nil {
				return nil, err
			}
		}
		return out, nil
	})
}
