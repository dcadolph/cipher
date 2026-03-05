package cipher

import "errors"

// ErrEncode is the sentinel returned when encryption fails. Concrete
// errors wrap ErrEncode so callers can match with errors.Is.
var ErrEncode = errors.New("encode")

// ErrDecode is the sentinel returned when decryption fails. Concrete
// errors wrap ErrDecode so callers can match with errors.Is.
var ErrDecode = errors.New("decode")

// ErrNoKeyGroups is returned when an Encoder has no key groups available.
var ErrNoKeyGroups = errors.New("no key groups configured")

// ErrEmpty is returned when there is nothing to encrypt in the input.
var ErrEmpty = errors.New("nothing to encrypt")

// ErrUnsupportedFormat is returned for formats this library does not handle.
var ErrUnsupportedFormat = errors.New("unsupported format")

// ErrAlreadyEncrypted is returned when an Encoder is asked to encrypt data
// that already contains sops metadata. Callers may match this with
// errors.Is to skip already-encrypted files.
var ErrAlreadyEncrypted = errors.New("already encrypted")

// ErrNotEncrypted is returned when a Decoder is asked to decrypt data that
// is not sops-encrypted. Callers may match this with errors.Is to skip
// plain files.
var ErrNotEncrypted = errors.New("not encrypted")

// ErrParse is returned when input bytes cannot be parsed as the requested
// format. Use this with errors.Is to tell "this file is corrupt" apart
// from "this file is plaintext" (ErrNotEncrypted).
var ErrParse = errors.New("parse failed")

// ErrOrphanRecipient is returned when RemoveRecipient would leave the
// file with zero remaining master keys, which would make the payload
// undecryptable forever. Set RemoveRecipientOptions.AllowOrphan to
// proceed anyway.
var ErrOrphanRecipient = errors.New("would orphan secret (no recipients remain)")

// ErrTooLarge is returned when the input ciphertext exceeds the
// configured size limit. A small encrypted blob can expand to large
// plaintext during parsing, so callers handling untrusted input should
// set DecoderOptions.MaxCiphertextBytes to a sensible upper bound.
var ErrTooLarge = errors.New("ciphertext exceeds size limit")
