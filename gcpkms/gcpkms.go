// Package gcpkms provides a cipher.KeyProvider backed by Google Cloud KMS.
//
// Recipient identifiers are GCP KMS resource IDs of the form
//
//	projects/<project>/locations/<location>/keyRings/<ring>/cryptoKeys/<key>
//
// All resource IDs share a single key group. Any one identity with
// permission on any key decrypts.
//
// # Credentials
//
// The provider does not read credentials itself. At encrypt and
// decrypt time, sops uses Google application-default credentials:
//
//   - GOOGLE_APPLICATION_CREDENTIALS pointing at a service account
//     JSON file
//   - gcloud user credentials
//   - Workload Identity / metadata server when running on GCP
//
// # Quick start
//
//	import (
//	    "github.com/dcadolph/cipher"
//	    "github.com/dcadolph/cipher/gcpkms"
//	)
//
//	kp, err := gcpkms.NewProvider(
//	    "projects/p/locations/global/keyRings/r/cryptoKeys/k",
//	)
//	if err != nil { /* ... */ }
//	enc := cipher.NewEncoder(kp)
package gcpkms

import (
	"context"
	"fmt"
	"strings"

	"github.com/getsops/sops/v3"
	sopsgcpkms "github.com/getsops/sops/v3/gcpkms"

	"github.com/dcadolph/cipher"
	"github.com/dcadolph/cipher/internal/strutil"
)

// Provider is a cipher.KeyProvider that wraps each GCP KMS resource ID
// in a master key. All resource IDs share a single key group.
type Provider struct {
	// ResourceIDs is the list of GCP KMS resource IDs of the form
	// projects/.../locations/.../keyRings/.../cryptoKeys/...
	ResourceIDs []string
}

// NewProvider returns a cipher.KeyProvider for the given GCP KMS
// resource IDs. Empty/whitespace-only entries are dropped. Returns an
// error if no usable IDs remain or any ID is malformed. Each ID must
// take the form
// projects/<p>/locations/<l>/keyRings/<r>/cryptoKeys/<k>, with an
// optional /cryptoKeyVersions/<v> suffix.
func NewProvider(resourceIDs ...string) (cipher.KeyProvider, error) {
	cleaned := strutil.TrimEmpty(resourceIDs)
	if len(cleaned) == 0 {
		return nil, fmt.Errorf("cipher/gcpkms: at least one resource ID required")
	}
	for _, id := range cleaned {
		if err := validateResourceID(id); err != nil {
			return nil, fmt.Errorf("cipher/gcpkms: resource ID %q: %w", id, err)
		}
	}
	return &Provider{ResourceIDs: cleaned}, nil
}

// MustNewProvider wraps NewProvider and panics on error. Mirrors
// regexp.MustCompile and template.Must from the standard library:
// use only at init-time or in tests where construction failure is a
// developer error.
func MustNewProvider(resourceIDs ...string) cipher.KeyProvider {
	kp, err := NewProvider(resourceIDs...)
	if err != nil {
		panic(err)
	}
	return kp
}

// KeyGroups returns a single key group with one GCP KMS master key per
// resource ID. Implements cipher.KeyProvider.
func (p *Provider) KeyGroups(_ context.Context) ([]sops.KeyGroup, error) {
	if p == nil || len(p.ResourceIDs) == 0 {
		return nil, fmt.Errorf("cipher/gcpkms: no resource IDs configured")
	}
	group := make(sops.KeyGroup, 0, len(p.ResourceIDs))
	for _, id := range p.ResourceIDs {
		group = append(group, sopsgcpkms.NewMasterKeyFromResourceID(id))
	}
	return []sops.KeyGroup{group}, nil
}

// validateResourceID verifies the standard projects/.../locations/.../
// keyRings/.../cryptoKeys/... shape, optionally suffixed with
// cryptoKeyVersions/<v>.
func validateResourceID(id string) error {
	parts := strings.Split(id, "/")
	switch len(parts) {
	case 8, 10:
	default:
		return fmt.Errorf("expected 8 or 10 segments, got %d", len(parts))
	}
	want := []string{"projects", "", "locations", "", "keyRings", "", "cryptoKeys", ""}
	if len(parts) == 10 {
		want = append(want, "cryptoKeyVersions", "")
	}
	for i, label := range want {
		if i%2 == 0 {
			if parts[i] != label {
				return fmt.Errorf("segment %d is %q, want %q", i, parts[i], label)
			}
			continue
		}
		if parts[i] == "" {
			return fmt.Errorf("segment %d (after %q) is empty", i, want[i-1])
		}
	}
	return nil
}
