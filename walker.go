package cipher

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"sync"

	"github.com/spf13/afero"

	"github.com/dcadolph/cipher/internal/atomic"
)

// WalkOptions tunes EncodeWalkWith, DecodeWalkWith, and RotateWalkWith.
type WalkOptions struct {
	// FollowSymlinks, when true, allows the walk to descend into symlinked
	// directories. Default false.
	FollowSymlinks bool
	// Parallelism is the maximum number of files processed concurrently.
	// Zero or one means sequential.
	Parallelism int
	// BackupSuffix, when non-empty, instructs the walker to copy each
	// original file to <path><suffix> before overwriting it. The backup
	// is retained on disk after the walk so callers can diff or revert.
	// Backups for files that were skipped are not created.
	BackupSuffix string
	// OnFile is called for every visited file after a successful encode,
	// decode, or rotate. It receives the path and the resulting byte count.
	// Nil is treated as a no-op.
	OnFile func(path string, bytes int)
	// OnSkip is called when a file is skipped (ErrAlreadyEncrypted,
	// ErrNotEncrypted, ErrEmpty, or matcher rejection). Nil is treated
	// as a no-op.
	OnSkip func(path string, reason error)
}

// EncodeWalk walks root on files and encrypts every file matched by any
// of the supplied matchers using enc. Empty matchers means every file
// is matched. Already-encrypted files are skipped.
func EncodeWalk(
	ctx context.Context, files afero.Fs, root string,
	enc Encoder, matchers []FileMatcher,
) error {
	return EncodeWalkWith(ctx, files, root, enc, matchers, WalkOptions{})
}

// EncodeWalkWith is EncodeWalk with explicit options.
func EncodeWalkWith(
	ctx context.Context, files afero.Fs, root string,
	enc Encoder, matchers []FileMatcher, opts WalkOptions,
) error {
	if files == nil {
		panic("cipher: EncodeWalkWith: filesystem required")
	}
	if enc == nil {
		panic("cipher: EncodeWalkWith: encoder required")
	}
	return runWalk(ctx, files, root, matchers, opts,
		func(ctx context.Context, fs afero.Fs, path string, info fs.FileInfo) error {
			data, err := afero.ReadFile(fs, path)
			if err != nil {
				return fmt.Errorf("cipher: read %q: %w", path, err)
			}
			out, err := enc.Encode(ctx, path, data)
			switch {
			case errors.Is(err, ErrAlreadyEncrypted), errors.Is(err, ErrEmpty):
				notify(opts.OnSkip, path, err)
				return nil
			case err != nil:
				return fmt.Errorf("cipher: encode %q: %w", path, err)
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

// DecodeWalk walks root on files and decrypts every file matched by
// any of the supplied matchers using dec. Empty matchers means every
// file is matched. Plain (non-encrypted) files are skipped.
func DecodeWalk(
	ctx context.Context, files afero.Fs, root string,
	dec Decoder, matchers []FileMatcher,
) error {
	return DecodeWalkWith(ctx, files, root, dec, matchers, WalkOptions{})
}

// DecodeWalkWith is DecodeWalk with explicit options.
func DecodeWalkWith(
	ctx context.Context, files afero.Fs, root string,
	dec Decoder, matchers []FileMatcher, opts WalkOptions,
) error {
	if files == nil {
		panic("cipher: DecodeWalkWith: filesystem required")
	}
	if dec == nil {
		panic("cipher: DecodeWalkWith: decoder required")
	}
	return runWalk(ctx, files, root, matchers, opts,
		func(ctx context.Context, fs afero.Fs, path string, info fs.FileInfo) error {
			data, err := afero.ReadFile(fs, path)
			if err != nil {
				return fmt.Errorf("cipher: read %q: %w", path, err)
			}
			out, err := dec.Decode(ctx, path, data)
			switch {
			case errors.Is(err, ErrNotEncrypted):
				notify(opts.OnSkip, path, err)
				return nil
			case err != nil:
				return fmt.Errorf("cipher: decode %q: %w", path, err)
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

// errMatcherRejected is the reason reported to WalkOptions.OnSkip when
// a path is rejected by the matcher chain.
var errMatcherRejected = errors.New("matcher rejected")

// combineMatchers returns a single matcher equivalent to "any of matchers."
// An empty slice resolves to MatchAll so a walker invoked with no
// matchers visits every file.
func combineMatchers(matchers []FileMatcher) FileMatcher {
	if len(matchers) == 0 {
		return MatchAll()
	}
	if len(matchers) == 1 {
		return matchers[0]
	}
	return MatchAnyOf(matchers...)
}

// notify invokes cb if non-nil.
func notify[T any](cb func(string, T), path string, val T) {
	if cb != nil {
		cb(path, val)
	}
}

// writeBackup, when suffix is non-empty, writes the original file
// contents to path+suffix using atomic.WriteFile. Returns nil for empty
// suffixes. Failures abort the per-file work and leave the destination
// untouched.
func writeBackup(files afero.Fs, path string, data []byte, info fs.FileInfo, suffix string) error {
	if suffix == "" {
		return nil
	}
	backupPath := path + suffix
	if err := atomic.WriteFile(files, backupPath, data, info.Mode().Perm()); err != nil {
		return fmt.Errorf("cipher: backup %q -> %q: %w", path, backupPath, err)
	}
	return nil
}

// walkItem pairs a file path with its FileInfo.
type walkItem struct {
	path string
	info fs.FileInfo
}

// walkDoFunc is the per-file work performed by runWalk.
type walkDoFunc func(ctx context.Context, files afero.Fs, path string, info fs.FileInfo) error

// runWalk enumerates files under root that match matchers (or all
// files, when matchers is empty), then runs do for each one either
// sequentially (Parallelism <= 1) or concurrently with a bounded
// semaphore. On the first do error in the parallel case, the context
// passed to remaining workers is cancelled and the function returns
// the first observed error after in-flight work drains.
func runWalk(
	ctx context.Context, files afero.Fs, root string,
	matchers []FileMatcher, opts WalkOptions,
	do walkDoFunc,
) error {
	matcher := combineMatchers(matchers)

	var items []walkItem
	walkErr := afero.Walk(files, root, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if !opts.FollowSymlinks && (info.Mode()&fs.ModeSymlink != 0) {
			return nil
		}
		if !matcher.Match(path) {
			notify(opts.OnSkip, path, errMatcherRejected)
			return nil
		}
		items = append(items, walkItem{path: path, info: info})
		return nil
	})
	if walkErr != nil {
		return walkErr
	}

	if opts.Parallelism <= 1 {
		for _, it := range items {
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := do(ctx, files, it.path, it.info); err != nil {
				return err
			}
		}
		return nil
	}
	return runParallel(ctx, files, items, opts.Parallelism, do)
}

// runParallel processes items via a bounded semaphore. The first error
// from any worker cancels remaining work; runParallel returns after
// in-flight workers finish and yields the first observed error.
func runParallel(
	ctx context.Context, files afero.Fs,
	items []walkItem, parallelism int, do walkDoFunc,
) error {
	sem := make(chan struct{}, parallelism)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstErr error

	subCtx, cancel := context.WithCancel(ctx)
	defer cancel()

loop:
	for _, it := range items {
		select {
		case sem <- struct{}{}:
		case <-subCtx.Done():
			break loop
		}
		wg.Add(1)
		go func(it walkItem) {
			defer wg.Done()
			defer func() { <-sem }()
			if err := do(subCtx, files, it.path, it.info); err != nil {
				mu.Lock()
				if firstErr == nil {
					firstErr = err
					cancel()
				}
				mu.Unlock()
			}
		}(it)
	}
	wg.Wait()

	if firstErr != nil {
		return firstErr
	}
	return ctx.Err()
}
