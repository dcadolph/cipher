package cipher

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"sync"

	"github.com/spf13/afero"

	"github.com/dcadolph/cipher/internal/atomic"
)

// ErrSymlinkCycle is reported to WalkOptions.OnSkip when FollowSymlinks
// is true and a symlink resolves to an ancestor already visited on this
// walk. The cyclic entry is skipped, the walk continues with siblings.
var ErrSymlinkCycle = errors.New("symlink resolves to ancestor (cycle)")

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
				return fmt.Errorf("read %q: %w", path, err)
			}
			out, err := enc.Encode(ctx, path, data)
			switch {
			case errors.Is(err, ErrAlreadyEncrypted), errors.Is(err, ErrEmpty):
				notify(opts.OnSkip, path, err)
				return nil
			case err != nil:
				return fmt.Errorf("encode %q: %w", path, err)
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
				return fmt.Errorf("read %q: %w", path, err)
			}
			out, err := dec.Decode(ctx, path, data)
			switch {
			case errors.Is(err, ErrNotEncrypted):
				notify(opts.OnSkip, path, err)
				return nil
			case err != nil:
				return fmt.Errorf("decode %q: %w", path, err)
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
		return fmt.Errorf("backup %q -> %q: %w", path, backupPath, err)
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

// enumerateFiles returns every file under root that matches matcher.
// When opts.FollowSymlinks is false, directory symlinks are skipped;
// file symlinks are skipped as well, matching the historical behavior.
// When opts.FollowSymlinks is true, symlinks are resolved and a
// visited-set of canonical paths prevents cycles. Cyclic symlinks
// produce an OnSkip notification carrying ErrSymlinkCycle.
func enumerateFiles(
	ctx context.Context, files afero.Fs, root string,
	opts WalkOptions, matcher FileMatcher,
) ([]walkItem, error) {
	if !opts.FollowSymlinks {
		return enumerateNoFollow(ctx, files, root, opts, matcher)
	}
	visited := make(map[string]struct{})
	var items []walkItem
	if err := enumerateFollow(ctx, files, root, opts, matcher, visited, &items); err != nil {
		return nil, err
	}
	return items, nil
}

// enumerateNoFollow uses afero.Walk and skips all symlinks. This is
// the historical behavior.
func enumerateNoFollow(
	ctx context.Context, files afero.Fs, root string,
	opts WalkOptions, matcher FileMatcher,
) ([]walkItem, error) {
	var items []walkItem
	err := afero.Walk(files, root, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if info.Mode()&fs.ModeSymlink != 0 {
			return nil
		}
		if !matcher.Match(path) {
			notify(opts.OnSkip, path, errMatcherRejected)
			return nil
		}
		items = append(items, walkItem{path: path, info: info})
		return nil
	})
	return items, err
}

// enumerateFollow recursively walks root, dereferencing symlinks and
// guarding against cycles by tracking canonical directory paths in
// visited. The visited keys are filepath.Clean(EvalSymlinks-style)
// resolutions, computed via canonicalDir; cycles trigger OnSkip with
// ErrSymlinkCycle and the offending subtree is dropped.
func enumerateFollow(
	ctx context.Context, files afero.Fs, path string,
	opts WalkOptions, matcher FileMatcher,
	visited map[string]struct{}, items *[]walkItem,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	info, isSymlink, err := lstatFile(files, path)
	if err != nil {
		return err
	}

	resolved := path
	if isSymlink {
		target, rerr := readlinkFile(files, path)
		if rerr != nil {
			return fmt.Errorf("readlink %q: %w", path, rerr)
		}
		resolved = absoluteTarget(path, target)
		info, _, err = lstatFile(files, resolved)
		if err != nil {
			return fmt.Errorf("stat symlink target %q -> %q: %w", path, resolved, err)
		}
	}

	if !info.IsDir() {
		if !matcher.Match(path) {
			notify(opts.OnSkip, path, errMatcherRejected)
			return nil
		}
		*items = append(*items, walkItem{path: path, info: info})
		return nil
	}

	canon := filepath.Clean(resolved)
	if _, seen := visited[canon]; seen {
		notify(opts.OnSkip, path, ErrSymlinkCycle)
		return nil
	}
	visited[canon] = struct{}{}

	entries, err := afero.ReadDir(files, resolved)
	if err != nil {
		return fmt.Errorf("readdir %q: %w", resolved, err)
	}
	for _, e := range entries {
		child := filepath.Join(path, e.Name())
		if err := enumerateFollow(ctx, files, child, opts, matcher, visited, items); err != nil {
			return err
		}
	}
	return nil
}

// lstatFile returns the FileInfo for path via Lstat when supported, or
// Stat otherwise. The second return reports whether the entry is itself
// a symlink (only meaningful when Lstat was available).
func lstatFile(files afero.Fs, path string) (fs.FileInfo, bool, error) {
	if ls, ok := files.(afero.Lstater); ok {
		info, lstatCalled, err := ls.LstatIfPossible(path)
		if err != nil {
			return nil, false, err
		}
		if lstatCalled {
			return info, info.Mode()&fs.ModeSymlink != 0, nil
		}
		return info, false, nil
	}
	info, err := files.Stat(path)
	if err != nil {
		return nil, false, err
	}
	return info, false, nil
}

// readlinkFile returns the target of the symlink at path. Returns an
// error if the filesystem does not support readlink.
func readlinkFile(files afero.Fs, path string) (string, error) {
	if lr, ok := files.(afero.LinkReader); ok {
		return lr.ReadlinkIfPossible(path)
	}
	return "", afero.ErrNoReadlink
}

// absoluteTarget resolves target against link's directory. Absolute
// targets are returned unchanged; relative targets are joined onto
// the link's parent so the result is usable as a filesystem path.
func absoluteTarget(link, target string) string {
	if filepath.IsAbs(target) {
		return target
	}
	return filepath.Join(filepath.Dir(link), target)
}

// runWalk enumerates files under root that match matchers (or all
// files, when matchers is empty), then runs do for each one either
// sequentially (Parallelism <= 1) or concurrently with a bounded
// semaphore. On the first do error in the parallel case, the context
// passed to remaining workers is canceled and the function returns
// the first observed error after in-flight work drains.
func runWalk(
	ctx context.Context, files afero.Fs, root string,
	matchers []FileMatcher, opts WalkOptions,
	do walkDoFunc,
) error {
	matcher := combineMatchers(matchers)

	items, walkErr := enumerateFiles(ctx, files, root, opts, matcher)
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
