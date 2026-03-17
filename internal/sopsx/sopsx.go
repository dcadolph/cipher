// Package sopsx wraps the unstable parts of the getsops/sops library
// (the cmd/sops/common helpers in particular) so the rest of cipher
// depends on a single, internal API surface. This contains breakage
// to one place if sops internals change between releases.
package sopsx

import (
	"errors"
	"fmt"
	"time"

	"github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/aes"
	"github.com/getsops/sops/v3/cmd/sops/common"
	"github.com/getsops/sops/v3/cmd/sops/formats"
	"github.com/getsops/sops/v3/config"
	"github.com/getsops/sops/v3/keyservice"
	"github.com/getsops/sops/v3/version"
)

// Format mirrors the sops format enum.
type Format = formats.Format

// ErrEmpty signals that the input had no branches to encrypt.
var ErrEmpty = errors.New("sopsx: empty input")

// ErrNoKeyGroups signals that no key groups were supplied for encryption.
var ErrNoKeyGroups = errors.New("sopsx: no key groups configured")

// ErrAlreadyEncrypted signals that the input is already sops-encrypted.
var ErrAlreadyEncrypted = errors.New("sopsx: already encrypted")

// ErrNotEncrypted signals that the input is not sops-encrypted.
var ErrNotEncrypted = errors.New("sopsx: not encrypted")

// ErrParse signals that the input could not be parsed as the requested
// format. Callers that need to distinguish "this is plaintext" from
// "this file is corrupt" should check ErrParse before ErrNotEncrypted.
var ErrParse = errors.New("sopsx: parse failed")

// ErrOrphanRecipient signals that a RemoveRecipient call would leave
// the encrypted file with zero remaining master keys, making the
// payload undecryptable forever. Callers that genuinely want this
// outcome must set RemoveRecipientInput.AllowOrphan.
var ErrOrphanRecipient = errors.New("sopsx: would orphan secret (no recipients remain)")

// ErrTooLarge signals that the input ciphertext exceeded the caller's
// MaxCiphertextBytes limit. Callers handling untrusted input should
// set this to a sensible upper bound.
var ErrTooLarge = errors.New("sopsx: ciphertext exceeds size limit")

// EncryptInput holds inputs for encrypting a single file's bytes.
type EncryptInput struct {
	// Path is the file path used to derive Format when Format is zero.
	Path string
	// Data is the plaintext file content.
	Data []byte
	// Format is the sops format. If zero, it is derived from Path.
	Format Format
	// KeyGroups are the sops key groups used to wrap the data key.
	KeyGroups []sops.KeyGroup
	// KeyServices are the key services used to wrap data keys. If empty,
	// a single local key service is used.
	KeyServices []keyservice.KeyServiceClient
	// Cipher is the sops cipher. If nil, aes.NewCipher() is used.
	Cipher sops.Cipher
	// EncryptedRegex restricts encryption to keys matching this regex.
	EncryptedRegex string
	// UnencryptedRegex excludes keys matching this regex from encryption.
	UnencryptedRegex string
	// EncryptedSuffix restricts encryption to keys with this suffix.
	EncryptedSuffix string
	// UnencryptedSuffix excludes keys with this suffix from encryption.
	UnencryptedSuffix string
	// MACOnlyEncrypted reduces MAC computation to encrypted leaves.
	MACOnlyEncrypted bool
	// ShamirThreshold is the number of key groups required to recover the
	// data key. Zero means default behavior.
	ShamirThreshold int
}

// Encrypt produces the encrypted bytes for the given input.
// Returns ErrAlreadyEncrypted when the input already carries sops metadata.
func Encrypt(in EncryptInput) ([]byte, error) {
	if len(in.KeyGroups) == 0 {
		return nil, ErrNoKeyGroups
	}
	if in.Format == 0 && in.Path != "" {
		in.Format = formats.FormatForPath(in.Path)
	}
	if IsEncrypted(in.Data, in.Format) {
		return nil, ErrAlreadyEncrypted
	}

	cipher := in.Cipher
	if cipher == nil {
		cipher = aes.NewCipher()
	}
	services := in.KeyServices
	if len(services) == 0 {
		services = []keyservice.KeyServiceClient{keyservice.NewLocalClient()}
	}

	store := common.StoreForFormat(in.Format, config.NewStoresConfig())
	branches, err := store.LoadPlainFile(in.Data)
	if err != nil {
		return nil, fmt.Errorf("sopsx: load plain: %w", err)
	}
	if len(branches) == 0 {
		return nil, ErrEmpty
	}

	tree := sops.Tree{
		FilePath: in.Path,
		Branches: branches,
		Metadata: sops.Metadata{
			KeyGroups:         in.KeyGroups,
			EncryptedRegex:    in.EncryptedRegex,
			UnencryptedRegex:  in.UnencryptedRegex,
			EncryptedSuffix:   in.EncryptedSuffix,
			UnencryptedSuffix: in.UnencryptedSuffix,
			MACOnlyEncrypted:  in.MACOnlyEncrypted,
			ShamirThreshold:   in.ShamirThreshold,
			Version:           version.Version,
			LastModified:      time.Now().UTC(),
		},
	}

	dataKey, genErrs := tree.GenerateDataKeyWithKeyServices(services)
	if len(genErrs) > 0 {
		return nil, fmt.Errorf("sopsx: generate data key: %w", errors.Join(genErrs...))
	}

	if err := common.EncryptTree(common.EncryptTreeOpts{
		DataKey: dataKey,
		Tree:    &tree,
		Cipher:  cipher,
	}); err != nil {
		return nil, fmt.Errorf("sopsx: encrypt tree: %w", err)
	}

	out, err := store.EmitEncryptedFile(tree)
	if err != nil {
		return nil, fmt.Errorf("sopsx: emit encrypted: %w", err)
	}
	return out, nil
}

// DecryptInput holds inputs for decrypting a single file's bytes.
type DecryptInput struct {
	// Path is the file path used to derive Format when Format is zero.
	Path string
	// Data is the encrypted file content.
	Data []byte
	// Format is the sops format. If zero, it is derived from Path.
	Format Format
	// KeyServices are the key services used to unwrap data keys. If empty,
	// a single local key service is used.
	KeyServices []keyservice.KeyServiceClient
	// DecryptionOrder is the order in which decryption methods are tried.
	// If empty, sops.DefaultDecryptionOrder is used.
	DecryptionOrder []string
	// IgnoreMAC, when true, skips message authentication code verification.
	IgnoreMAC bool
	// Cipher is the sops cipher. If nil, aes.NewCipher() is used.
	Cipher sops.Cipher
	// MaxCiphertextBytes is the maximum allowed input size in bytes.
	// Zero means no limit. Callers handling untrusted input should
	// set this to a sensible upper bound to defend against pathological
	// inputs that allocate large buffers during parsing.
	MaxCiphertextBytes int
}

// Decrypt produces the plaintext bytes for the given input.
// Returns ErrNotEncrypted when the input does not carry sops metadata.
func Decrypt(in DecryptInput) ([]byte, error) {
	if in.MaxCiphertextBytes > 0 && len(in.Data) > in.MaxCiphertextBytes {
		return nil, ErrTooLarge
	}
	if in.Format == 0 && in.Path != "" {
		in.Format = formats.FormatForPath(in.Path)
	}
	if !IsEncrypted(in.Data, in.Format) {
		return nil, ErrNotEncrypted
	}

	cipher := in.Cipher
	if cipher == nil {
		cipher = aes.NewCipher()
	}
	services := in.KeyServices
	if len(services) == 0 {
		services = []keyservice.KeyServiceClient{keyservice.NewLocalClient()}
	}
	order := in.DecryptionOrder
	if len(order) == 0 {
		order = sops.DefaultDecryptionOrder
	}

	store := common.StoreForFormat(in.Format, config.NewStoresConfig())
	tree, err := store.LoadEncryptedFile(in.Data)
	if err != nil {
		return nil, fmt.Errorf("sopsx: load encrypted: %w", err)
	}

	if _, err := common.DecryptTree(common.DecryptTreeOpts{
		Tree:            &tree,
		KeyServices:     services,
		DecryptionOrder: order,
		IgnoreMac:       in.IgnoreMAC,
		Cipher:          cipher,
	}); err != nil {
		return nil, fmt.Errorf("sopsx: decrypt tree: %w", err)
	}

	out, err := store.EmitPlainFile(tree.Branches)
	if err != nil {
		return nil, fmt.Errorf("sopsx: emit plain: %w", err)
	}
	return out, nil
}

// AddRecipientMode controls how AddRecipient appends new keys to an
// existing file's metadata.
type AddRecipientMode int

const (
	// AddRecipientFlatten merges all new keys into the file's first
	// existing key group (creating one if none exist). The resulting
	// file remains decryptable by any single recipient. This matches
	// the most common "give Bob access" intent.
	AddRecipientFlatten AddRecipientMode = iota
	// AddRecipientAsGroups appends the new key groups as additional
	// groups. With Shamir threshold defaults this turns the file into
	// a multi-group secret requiring multiple groups to decrypt.
	// Intended for explicit Shamir users.
	AddRecipientAsGroups
)

// AddRecipientInput holds inputs for adding recipients to an already
// encrypted file without re-encrypting the payload.
type AddRecipientInput struct {
	// Path is the file path used to derive Format when Format is zero.
	Path string
	// Data is the encrypted file content.
	Data []byte
	// Format is the sops format. If zero, derived from Path.
	Format Format
	// NewGroups are the key groups produced by the user's KeyProvider.
	// How they are merged depends on Mode.
	NewGroups []sops.KeyGroup
	// Mode controls how NewGroups are merged. The zero value is
	// AddRecipientFlatten.
	Mode AddRecipientMode
	// KeyServices used to unwrap the existing data key and to wrap it
	// for the new recipients. Empty defaults to a single local client.
	KeyServices []keyservice.KeyServiceClient
	// DecryptionOrder for unwrapping. Empty defaults to sops.DefaultDecryptionOrder.
	DecryptionOrder []string
	// MaxCiphertextBytes is the maximum allowed input size in bytes.
	// Zero means no limit.
	MaxCiphertextBytes int
}

// AddRecipient inserts new keys into the file's key groups and re-wraps
// the data key. The payload ciphertext is unchanged.
func AddRecipient(in AddRecipientInput) ([]byte, error) {
	if len(in.NewGroups) == 0 {
		return nil, fmt.Errorf("sopsx: no new groups supplied")
	}
	if in.MaxCiphertextBytes > 0 && len(in.Data) > in.MaxCiphertextBytes {
		return nil, ErrTooLarge
	}
	if in.Format == 0 && in.Path != "" {
		in.Format = formats.FormatForPath(in.Path)
	}
	if !IsEncrypted(in.Data, in.Format) {
		return nil, ErrNotEncrypted
	}
	services := in.KeyServices
	if len(services) == 0 {
		services = []keyservice.KeyServiceClient{keyservice.NewLocalClient()}
	}
	order := in.DecryptionOrder
	if len(order) == 0 {
		order = sops.DefaultDecryptionOrder
	}

	store := common.StoreForFormat(in.Format, config.NewStoresConfig())
	tree, err := store.LoadEncryptedFile(in.Data)
	if err != nil {
		return nil, fmt.Errorf("sopsx: load encrypted: %w", err)
	}
	dataKey, err := tree.Metadata.GetDataKeyWithKeyServices(services, order)
	if err != nil {
		return nil, fmt.Errorf("sopsx: get data key: %w", err)
	}

	switch in.Mode {
	case AddRecipientFlatten:
		var added sops.KeyGroup
		for _, g := range in.NewGroups {
			added = append(added, g...)
		}
		if len(tree.Metadata.KeyGroups) == 0 {
			tree.Metadata.KeyGroups = []sops.KeyGroup{added}
		} else {
			tree.Metadata.KeyGroups[0] = append(tree.Metadata.KeyGroups[0], added...)
		}
	case AddRecipientAsGroups:
		tree.Metadata.KeyGroups = append(tree.Metadata.KeyGroups, in.NewGroups...)
	default:
		return nil, fmt.Errorf("sopsx: unknown AddRecipientMode %d", in.Mode)
	}

	if errs := tree.Metadata.UpdateMasterKeysWithKeyServices(dataKey, services); len(errs) > 0 {
		return nil, fmt.Errorf("sopsx: update master keys: %w", errors.Join(errs...))
	}
	out, err := store.EmitEncryptedFile(tree)
	if err != nil {
		return nil, fmt.Errorf("sopsx: emit encrypted: %w", err)
	}
	return out, nil
}

// RemoveRecipientInput holds inputs for dropping master keys whose
// string identifier matches Identifiers from an encrypted file.
type RemoveRecipientInput struct {
	// Path is the file path used to derive Format when Format is zero.
	Path string
	// Data is the encrypted file content.
	Data []byte
	// Format is the sops format. If zero, derived from Path.
	Format Format
	// Identifiers is the list of master-key identifiers to remove.
	// Each value is compared against keys.MasterKey.ToString().
	Identifiers []string
	// DropEmptyGroups removes any key group that becomes empty after
	// the identifiers are removed.
	DropEmptyGroups bool
	// AllowOrphan, when true, permits removal that leaves the file with
	// zero remaining master keys. The resulting file is undecryptable
	// forever. Required to make data destruction explicit.
	AllowOrphan bool
	// MaxCiphertextBytes is the maximum allowed input size in bytes.
	// Zero means no limit.
	MaxCiphertextBytes int
}

// RemoveRecipient drops master keys from the file's key groups whose
// ToString() matches an entry in in.Identifiers. The payload is not
// decrypted; this operation only edits the wrapped data key entries.
func RemoveRecipient(in RemoveRecipientInput) ([]byte, error) {
	if len(in.Identifiers) == 0 {
		return nil, fmt.Errorf("sopsx: no identifiers supplied")
	}
	if in.MaxCiphertextBytes > 0 && len(in.Data) > in.MaxCiphertextBytes {
		return nil, ErrTooLarge
	}
	if in.Format == 0 && in.Path != "" {
		in.Format = formats.FormatForPath(in.Path)
	}
	if !IsEncrypted(in.Data, in.Format) {
		return nil, ErrNotEncrypted
	}

	store := common.StoreForFormat(in.Format, config.NewStoresConfig())
	tree, err := store.LoadEncryptedFile(in.Data)
	if err != nil {
		return nil, fmt.Errorf("sopsx: load encrypted: %w", err)
	}

	want := make(map[string]struct{}, len(in.Identifiers))
	for _, id := range in.Identifiers {
		want[id] = struct{}{}
	}
	groups := tree.Metadata.KeyGroups
	out := make([]sops.KeyGroup, 0, len(groups))
	removed := 0
	for _, g := range groups {
		kept := make(sops.KeyGroup, 0, len(g))
		for _, k := range g {
			if _, drop := want[k.ToString()]; drop {
				removed++
				continue
			}
			kept = append(kept, k)
		}
		if len(kept) == 0 && in.DropEmptyGroups {
			continue
		}
		out = append(out, kept)
	}
	if removed == 0 {
		return nil, fmt.Errorf("sopsx: no matching recipients found")
	}
	if !in.AllowOrphan && countKeys(out) == 0 {
		return nil, ErrOrphanRecipient
	}
	tree.Metadata.KeyGroups = out

	emitted, err := store.EmitEncryptedFile(tree)
	if err != nil {
		return nil, fmt.Errorf("sopsx: emit encrypted: %w", err)
	}
	return emitted, nil
}

// Info summarizes the metadata of a sops-encrypted file without
// requiring decryption.
type Info struct {
	// Format is the detected sops format.
	Format Format
	// Version is the sops version string recorded in the metadata.
	Version string
	// MAC is the message-authentication-code stored in metadata.
	MAC string
	// LastModified is the metadata's last-modified timestamp formatted
	// as RFC 3339, or empty if absent.
	LastModified string
	// EncryptedRegex / UnencryptedRegex / Suffix mirror the metadata.
	EncryptedRegex    string
	UnencryptedRegex  string
	EncryptedSuffix   string
	UnencryptedSuffix string
	// MACOnlyEncrypted mirrors the metadata flag.
	MACOnlyEncrypted bool
	// ShamirThreshold is the metadata's Shamir threshold (0 means default).
	ShamirThreshold int
	// Groups holds the recipient identifiers per key group, in metadata order.
	Groups [][]RecipientInfo
}

// RecipientInfo describes a single master key recorded in a file's metadata.
type RecipientInfo struct {
	// Type is the master key type (age, kms, gcp_kms, hc_vault, azure_kv, pgp).
	Type string
	// Identifier is the master key's string identifier (recipient,
	// ARN, resource ID, URI, URL, or fingerprint).
	Identifier string
}

// Inspect parses data as a sops-encrypted file and returns the metadata
// without decrypting the payload. Returns ErrNotEncrypted if the data
// parses but carries no sops metadata, and ErrParse if the data does
// not parse as the requested format.
func Inspect(data []byte, format Format) (*Info, error) {
	if len(data) == 0 {
		return nil, ErrNotEncrypted
	}
	store := common.StoreForFormat(format, config.NewStoresConfig())
	tree, err := store.LoadEncryptedFile(data)
	switch {
	case errors.Is(err, sops.MetadataNotFound):
		return nil, ErrNotEncrypted
	case err != nil:
		return nil, fmt.Errorf("%w: %w", ErrParse, err)
	}
	meta := tree.Metadata
	if meta.MessageAuthenticationCode == "" && len(meta.KeyGroups) == 0 {
		return nil, ErrNotEncrypted
	}
	out := &Info{
		Format:            format,
		Version:           meta.Version,
		MAC:               meta.MessageAuthenticationCode,
		EncryptedRegex:    meta.EncryptedRegex,
		UnencryptedRegex:  meta.UnencryptedRegex,
		EncryptedSuffix:   meta.EncryptedSuffix,
		UnencryptedSuffix: meta.UnencryptedSuffix,
		MACOnlyEncrypted:  meta.MACOnlyEncrypted,
		ShamirThreshold:   meta.ShamirThreshold,
	}
	if !meta.LastModified.IsZero() {
		out.LastModified = meta.LastModified.UTC().Format(time.RFC3339)
	}
	out.Groups = make([][]RecipientInfo, len(meta.KeyGroups))
	for i, g := range meta.KeyGroups {
		group := make([]RecipientInfo, 0, len(g))
		for _, k := range g {
			group = append(group, RecipientInfo{
				Type:       k.TypeToIdentifier(),
				Identifier: k.ToString(),
			})
		}
		out.Groups[i] = group
	}
	return out, nil
}

// countKeys returns the total number of master keys across all groups.
func countKeys(groups []sops.KeyGroup) int {
	n := 0
	for _, g := range groups {
		n += len(g)
	}
	return n
}

// IsEncrypted reports whether data parses as a sops-encrypted file of the
// given format. Returns false for unencrypted data and for data that
// fails to parse as the format's encrypted shape.
func IsEncrypted(data []byte, format Format) bool {
	if len(data) == 0 {
		return false
	}
	store := common.StoreForFormat(format, config.NewStoresConfig())
	tree, err := store.LoadEncryptedFile(data)
	if err != nil {
		return false
	}
	if tree.Metadata.MessageAuthenticationCode != "" {
		return true
	}
	for _, g := range tree.Metadata.KeyGroups {
		if len(g) > 0 {
			return true
		}
	}
	return false
}
