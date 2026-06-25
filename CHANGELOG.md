# Changelog

All notable changes to cipher are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Added

- Godoc examples for every cloud backend and for httpmw. Each package now renders runnable snippets on pkg.go.dev.
- Fuzz tests for `MatchExt`, `MatchGlob`, and `MatchRegex`. Targets must never panic regardless of input.

## v0.2.1 (2026-06-24)

### Added

- Round trip integration tests for the pgp backend using a throwaway gpg keyring and the aws kms backend using a localstack container. CI runs both on every pull request so real api drift is caught early.

## v0.2.0 (2026-06-24)

### Breaking

- `EncoderOptions.MACOnlyEncrypted bool` is now `EncoderOptions.MAC MACMode`. Library callers using `MACOnlyEncrypted: true` should switch to `MAC: cipher.MACOnEncrypted`. The tri-state `MACInherit / MACOnAll / MACOnEncrypted` lets router rules flip the mode in either direction instead of only enabling it.
- `kms.NewProvider(opts, ...arns)` is renamed to `kms.NewProviderWith(opts, ...arns)`. A new `kms.NewProvider(...arns)` matches the other backends and uses default credentials with no encryption context. Same rename for `MustNewProvider`.

### Added

- `recipient_identity_format_test.go` pins the `ToString()` format that `RemoveRecipient` uses, per backend. A sops upgrade that changes the format breaks CI here.
- Doc note on `KeyProvider.KeyGroups` clarifying that `ctx` is currently ignored by built-in providers and will be honored once sops master keys plumb context through.
- Vault Transit integration test under the `integration` build tag. CI runs it on every PR against a dev vault container so real encrypt and decrypt are exercised end to end.

### Fixed

- Walker callbacks `OnFile` and `OnSkip` now serialize when `Parallelism > 1`. Previous behavior could race when user callbacks mutated shared state.
- `internal/atomic.WriteFile` now `fsync`s the temp file before close and best-effort `fsync`s the parent directory after rename. Package doc explains what is and is not durable.
- `httpmw` package doc now spells out the streaming constraint: the buffered response writer drops `http.Flusher`, `http.Hijacker`, and `io.ReaderFrom`. Server-Sent Events, websocket upgrades, and incremental flush handlers must not be wrapped with `EncryptResponseBody`.
- Edit `clear()` comment rewritten to match what the code actually delivers. Upstream sops copies persist in freed-but-not-zeroed heap memory and cipher cannot reach them.

### Changed

- `internal/util` renamed to `internal/strutil`. Revive flagged `util` as a meaningless package name.
- Bumped `golangci-lint` to v2.6.0 and added the `lll` linter with a 100 column cap.
- Switched `govulncheck` to the official `golang/govulncheck-action@v1`.

## v0.1.1 (2026-06-20)

Initial release.

- `brew install dcadolph/tap/cipher` for one-shot install on macOS and Linux.
- GoReleaser builds binaries for linux, darwin, and windows on amd64 and arm64.
- The release hook templates `Formula/cipher.rb` and pushes it to `dcadolph/homebrew-tap`.
