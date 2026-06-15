// Package main demonstrates EncodeWalkWith over an in-memory afero
// filesystem. Eight workers walk a tree of YAML and JSON files and
// encrypt each in parallel using age. The example prints a summary
// of files encrypted, skipped, and any failures.
package main

import (
	"context"
	"fmt"
	"log"
	"sync/atomic"

	"github.com/spf13/afero"

	"github.com/dcadolph/cipher"
	"github.com/dcadolph/cipher/age"
)

func main() {
	ctx := context.Background()

	id, err := age.GenerateIdentity()
	if err != nil {
		log.Fatalf("generate age identity: %v", err)
	}

	provider, err := age.NewProvider(id.Recipient)
	if err != nil {
		log.Fatalf("age provider: %v", err)
	}
	enc := cipher.NewEncoder(provider)

	fs := afero.NewMemMapFs()
	seedTree(fs)

	var encrypted, skipped int64
	opts := cipher.WalkOptions{
		Parallelism: 8,
		OnFile: func(path string, bytes int) {
			atomic.AddInt64(&encrypted, 1)
		},
		OnSkip: func(path string, reason error) {
			atomic.AddInt64(&skipped, 1)
			fmt.Printf("skip %s: %v\n", path, reason)
		},
	}

	matchers := []cipher.FileMatcher{cipher.MatchExt("yaml", "yml", "json")}
	if err := cipher.EncodeWalkWith(ctx, fs, "/secrets", enc, matchers, opts); err != nil {
		log.Fatalf("walk: %v", err)
	}

	fmt.Printf("\nencrypted %d files, skipped %d\n", encrypted, skipped)
}

// seedTree populates fs with a small set of plaintext secret files
// plus a non-matching binary file to demonstrate matcher filtering.
func seedTree(fs afero.Fs) {
	//nolint:gosec // Example seed data, not real credentials.
	files := map[string]string{
		"/secrets/prod/db.yaml":   "user: admin\npass: hunter2\n",
		"/secrets/prod/api.yaml":  "token: prod-abc-123\n",
		"/secrets/stage/db.yaml":  "user: stage\npass: temp\n",
		"/secrets/stage/api.json": `{"token":"stage-xyz-789"}`,
		"/secrets/dev/db.yaml":    "user: dev\npass: dev\n",
		"/secrets/notes.txt":      "(plain notes, should be skipped by matcher)",
	}
	for path, body := range files {
		if err := afero.WriteFile(fs, path, []byte(body), 0o600); err != nil {
			panic(err)
		}
	}
}
