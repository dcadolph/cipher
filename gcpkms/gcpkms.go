// Package gcpkms provides a cipher.KeyProvider backed by Google Cloud KMS.
package gcpkms

import (
	"context"
	"fmt"
	"strings"

	"github.com/getsops/sops/v3"
	sopsgcpkms "github.com/getsops/sops/v3/gcpkms"

	"github.com/dcadolph/cipher"
)

// Provider is a cipher.KeyProvider that wraps each GCP KMS resource ID
// in a master key. All resource IDs share a single key group.
type Provider struct {
	// ResourceIDs is the list of GCP KMS resource IDs of the form
	// projects/.../locations/.../keyRings/.../cryptoKeys/...
	ResourceIDs []string
}

// NewProvider returns a cipher.KeyProvider for the given GCP KMS
// resource IDs. Panics if no resource IDs are supplied.
func NewProvider(resourceIDs ...string) cipher.KeyProvider {
	cleaned := trimEmpty(resourceIDs)
	if len(cleaned) == 0 {
		panic("cipher/gcpkms: NewProvider: at least one resource ID required")
	}
	return &Provider{ResourceIDs: cleaned}
}

// NewProviderFromCSV returns a Provider for a comma-separated list of
// resource IDs. Panics if csv contains no usable IDs.
func NewProviderFromCSV(csv string) cipher.KeyProvider {
	return NewProvider(strings.Split(csv, ",")...)
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

// trimEmpty returns in with empty/whitespace-only entries removed.
func trimEmpty(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}
