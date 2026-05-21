<p align="center">
  <img src="internal/logo/cipher.png" alt="cipher" width="200" height="200">
</p>

# cipher

A Go library and CLI for [sops](https://github.com/getsops/sops) that fills
the gap sops itself left open. It adds:

- programmatic encryption
- key rotation
- recipient management
- a project-wide pre-commit safety net

Sops ships a stable Go API for decryption only (`decrypt.File` and
`decrypt.Data`). Programmatic encryption is not part of that stable
surface. To encrypt from Go today, you have to assemble a `sops.Tree`,
build `KeyGroups`, pick a `Cipher`, call internal helpers under
`cmd/sops/common`, and emit through a per-format store. That is roughly
fifty lines of boilerplate. It has been copy-pasted from
[issue #1094](https://github.com/getsops/sops/issues/1094) for years.

cipher collapses all of that into a small set of single-method
interfaces with sensible defaults. It also covers the operations that
come after encryption:

- rotate the data key
- add or remove recipients
- walk a directory in parallel
- edit a file in `$EDITOR`
- drive everything from `.sops.yaml`

```go
enc := cipher.NewEncoder(age.NewProvider("age1qyqsz..."))
ciphertext, err := enc.Encode(ctx, "secrets.yaml", plain)
```

## What it does

| Capability | API |
| ---------- | --- |
| Encrypt or decrypt a single file in memory | `Encoder.Encode`, `Decoder.Decode` |
| Walk a directory tree (sequential or parallel) | `EncodeWalk`, `DecodeWalk`, `RotateWalk` |
| Decrypt, mutate, re-encrypt atomically | `Edit`, `EditWith` |
| Rotate the data key (new ciphertext, same recipients) | `Rotate`, `RotateWalk` |
| Add a recipient without re-encrypting the payload | `AddRecipient` |
| Revoke a recipient | `RemoveRecipient` |
| List recipients and metadata without decrypting | `Inspect`, `InspectPath` |
| Diff recipients across two encrypted versions | `DiffRecipients`, `DiffRecipientsPath` |
| Detect already-encrypted files | `IsEncrypted`, `IsEncryptedPath` |
| Route per-path key selection from `.sops.yaml` | `sopsconfig.Config.Router`, `NewRoutedEncoder` |
| Shamir threshold rule builder | `NewShamirRule` |
| Backup originals on write | `WalkOptions.BackupSuffix`, `EditOptions.BackupSuffix` |
| Reject plaintext secrets in git | `precommit.Checker`, `cipher precommit` |
| HTTP middleware | `cipher/httpmw` |
| OpenTelemetry tracing | `cipher/otelcipher` |
| Test helpers | `cipher/ciphertest` |
| Size guard against oversized inputs | `EncoderOptions.MaxPlaintextBytes` |
| End-to-end CLI | `cmd/cipher` |

## Backends

Every backend implements one interface (`KeyProvider`) and lives in its
own subpackage. Compose them, swap them, mix them.

| Backend | Subpackage | Constructor |
| ------- | ---------- | ----------- |
| age | `cipher/age` | `age.NewProvider(recipients...)` |
| AWS KMS | `cipher/kms` | `kms.NewProvider(arns...)` |
| GCP KMS | `cipher/gcpkms` | `gcpkms.NewProvider(resourceIDs...)` |
| HashiCorp Vault Transit | `cipher/vault` | `vault.NewProvider(uris...)` |
| Azure Key Vault | `cipher/azkv` | `azkv.NewProvider(urls...)` |
| GPG / PGP | `cipher/pgp` | `pgp.NewProvider(fingerprints...)` |

To combine backends:

- `cipher.MergeProviders` puts every backend's keys into a single key
  group.
- `cipher.ChainKeyProviders` keeps each backend in its own key group.

## Install

```sh
go get github.com/dcadolph/cipher
go install github.com/dcadolph/cipher/cmd/cipher@latest
```

Requires Go 1.23 or newer.

## Quick start

### Encrypt in memory

```go
ctx := context.Background()
enc := cipher.NewEncoder(age.NewProvider("age1qyqsz..."))
ciphertext, err := enc.Encode(ctx, "secrets.yaml", []byte("foo: bar\n"))
```

### Decrypt in memory

```go
dec := cipher.NewDecoder()
plain, err := dec.Decode(ctx, "secrets.yaml", ciphertext)
```

`Decoder` uses the standard sops identity sources:

- `SOPS_AGE_KEY`
- `SOPS_AGE_KEY_FILE`
- AWS credentials
- GCP credentials
- and so on

The same environment that drives the `sops` binary works here.

### Walk a directory with bounded parallelism

```go
err := cipher.EncodeWalkWith(
    ctx, afero.NewOsFs(), "./secrets",
    cipher.NewEncoder(age.NewProvider(recipient)),
    []cipher.FileMatcher{cipher.MatchExt("yaml", "yml", "json")},
    cipher.WalkOptions{
        Parallelism: 8,
        OnFile: func(p string, n int) { log.Printf("encrypted %s (%d)", p, n) },
        OnSkip: func(p string, reason error) { log.Printf("skip %s: %v", p, reason) },
    },
)
```

Already-encrypted files are skipped. Files are written atomically using
a temp file plus rename, so a failed write never leaves a half-encrypted
secret on disk.

### Edit a file in `$EDITOR`

```go
err := cipher.Edit(ctx, afero.NewOsFs(), "secrets.yaml", enc, dec,
    func(plain []byte) ([]byte, error) {
        return append(plain, []byte("new_key: value\n")...), nil
    },
)
```

If `fn` is read-only, return the same bytes. `Edit` skips the write.

### Drive everything from `.sops.yaml`

```go
cfg, _ := sopsconfig.LoadFromDir(".")
router := cfg.Router(nil)
enc := cipher.NewRoutedEncoder(router, cipher.EncoderOptions{})

ciphertext, err := enc.Encode(ctx, "secrets/prod/db.yaml", plain)
```

The Router consults the project's `.sops.yaml` on every call. Matching
semantics are identical to the `sops` CLI's `creation_rules`.

### Rotate the data key

```go
rotated, err := cipher.Rotate(ctx, "secrets.yaml", ciphertext, enc, dec)
```

Same recipients, new data key. Use `RotateWalk` over a directory.

### Add or remove a recipient

```go
withBob, err := cipher.AddRecipient(
    ctx, "secrets.yaml", ciphertext,
    age.NewProvider("age1bob..."),
    cipher.DecoderOptions{},
)
withoutBob, err := cipher.RemoveRecipient(
    ctx, "secrets.yaml", withBob, "age1bob...",
)
```

Only the wrapped data key changes. The encrypted payload is
byte-for-byte identical.

## Concepts

Four single-method interfaces. Each has a matching `Func` adapter so a
plain function satisfies it (the `http.HandlerFunc` style).

| Interface | Method | Purpose |
| --------- | ------ | ------- |
| `Encoder` | `Encode(ctx, path, data) ([]byte, error)` | Encrypts file bytes. |
| `Decoder` | `Decode(ctx, path, data) ([]byte, error)` | Decrypts file bytes. |
| `KeyProvider` | `KeyGroups(ctx) ([]sops.KeyGroup, error)` | Supplies recipients. |
| `FileMatcher` | `Match(path) bool` | Selects files during a walk. |
| `Router` | `Resolve(path) (KeyProvider, EncoderOptions, error)` | Picks recipients per path. |
| `Logger` | `Debugf / Infof / Warnf` | Optional observability hook. |

Available matchers:

- `MatchAll`
- `MatchNone`
- `MatchRegex`
- `MatchExt`
- `MatchGlob`
- `MatchAnyOf`
- `MatchAllOf`
- `MatchNot`

Encoder and Decoder options expose every sops knob:

- `EncryptedRegex`
- `UnencryptedRegex`
- `EncryptedSuffix`
- `UnencryptedSuffix`
- `MACOnlyEncrypted`
- `ShamirThreshold`
- custom `KeyServiceClient`
- custom `sops.Cipher`
- `Logger` (zap, logrus, slog, or anything matching the interface)
- `OnEncrypt` and `OnDecrypt` callbacks

## CLI

```
cipher encrypt PATH
cipher decrypt PATH
cipher edit PATH
cipher rotate PATH...
cipher walk encrypt ROOT
cipher walk decrypt ROOT
cipher walk rotate ROOT
cipher add-recipient PATH --age AGE1...
cipher remove-recipient PATH RECIPIENT_STRING
cipher precommit
cipher version
```

Recipient flags accepted by encrypt, edit, rotate, walk, and
add-recipient:

- `--age`
- `--kms`
- `--gcp-kms`
- `--vault-uri`
- `--azure-keyvault`
- `--pgp`
- `--config` (load `.sops.yaml`)

Every command supports `-i/--in-place`, `-o/--output`, and stdin/stdout
via `PATH == "-"`. Walks take `--ext`, `--regex`, and `--parallel`.

### Git pre-commit hook

```bash
#!/usr/bin/env bash
exec cipher precommit
```

Drop this into `.git/hooks/pre-commit` or your `pre-commit` framework.
The hook does three things:

1. Walks the files in `git diff --cached`.
2. Compares each staged blob against the project's `.sops.yaml`.
3. Exits non-zero with a list of paths if any match a creation rule but
   are not sops-encrypted.

The first time a teammate forgets to encrypt before committing, this
saves the day.

## Inspect and diff

Read recipients out of an encrypted file without decrypting it:

```go
info, err := cipher.InspectPath("secrets.yaml", data)
for _, group := range info.Groups {
    for _, r := range group {
        fmt.Println(r.Type, r.Identifier)
    }
}
```

Diff two versions of the same secret. Useful for PR review:

```go
diff, err := cipher.DiffRecipientsPath("secrets.yaml", before, after)
for _, r := range diff.Added   { fmt.Println("+", r) }
for _, r := range diff.Removed { fmt.Println("-", r) }
```

## Shamir secret sharing

`NewShamirRule(match, threshold, providers...)` wires threshold-of-N
recovery across heterogeneous backends:

```go
rule := cipher.NewShamirRule(
    cipher.MatchExt("yaml"), 2,
    age.NewProvider("age1ops..."),
    kms.NewProvider("arn:aws:kms:..."),
    gcpkms.NewProvider("projects/..."),
)
enc := cipher.NewRoutedEncoder(cipher.NewRouter(rule), cipher.EncoderOptions{})
```

## HTTP middleware

```go
http.Handle("/secrets/", httpmw.DecryptRequestBody(
    cipher.NewDecoder(), httpmw.DefaultPathFunc,
)(myHandler))

http.Handle("/export/", httpmw.EncryptResponseBody(
    cipher.NewEncoder(age.NewProvider(recipient)), httpmw.DefaultPathFunc,
)(myHandler))
```

Behavior:

- Decryption failures return HTTP 400.
- Oversize bodies return HTTP 413 (configurable via `WithMaxBodyBytes`).
- The wrapped handler sees plaintext via `r.Body`.

## OpenTelemetry tracing

```go
tracer := otel.Tracer("my-service")
enc := otelcipher.WrapEncoder(cipher.NewEncoder(kp), tracer)
dec := otelcipher.WrapDecoder(cipher.NewDecoder(), tracer)
```

Each call emits a `cipher.Encode` or `cipher.Decode` span. Span
attributes include:

- `cipher.path`
- `cipher.plaintext_bytes`
- `cipher.ciphertext_bytes`

Errors are recorded on the span.

## Test helpers

```go
func TestMyHandler(t *testing.T) {
    kp, _ := ciphertest.NewProvider(t)
    enc := cipher.NewEncoder(kp)
    dec := cipher.NewDecoder()
    ciphertest.AssertRoundTrip(t, ctx, enc, dec,
        "secrets.yaml", []byte("foo: bar\n"), "foo: bar")
}
```

`NewProvider` generates a fresh age identity, sets `SOPS_AGE_KEY` in the
process environment, and returns a working `KeyProvider`. Tests that use
it must not call `t.Parallel`, because the env is process-global.

## Streaming and large files

Sops loads the entire file into memory before emitting. cipher inherits
that constraint. To fail fast on inputs that would blow your process
budget, set `EncoderOptions.MaxPlaintextBytes`:

```go
enc := cipher.NewEncoderWith(kp, cipher.EncoderOptions{
    MaxPlaintextBytes: 50 << 20, // 50 MiB
})
```

Streaming binary encrypt is not currently supported. Sops's data model
does not split a single file across chunks.

## Status

The public API surface is stable. The `internal/sopsx` package wraps
`github.com/getsops/sops/v3/cmd/sops/common` so a breaking change in
sops internals stays contained to a single file.

Package tree:

| Package | Purpose |
| ------- | ------- |
| `cipher` | Core interfaces, walker, ops, router, status, errors, logger. |
| `cipher/age` | KeyProvider for age recipients. |
| `cipher/kms` | KeyProvider for AWS KMS. |
| `cipher/gcpkms` | KeyProvider for GCP KMS. |
| `cipher/vault` | KeyProvider for HashiCorp Vault Transit. |
| `cipher/azkv` | KeyProvider for Azure Key Vault. |
| `cipher/pgp` | KeyProvider for GPG fingerprints. |
| `cipher/sopsconfig` | Parses `.sops.yaml` and returns a Router. |
| `cipher/precommit` | Git pre-commit safety check. |
| `cipher/httpmw` | HTTP middleware. |
| `cipher/otelcipher` | OpenTelemetry span wrappers. |
| `cipher/ciphertest` | Test helpers for code that uses cipher. |
| `cmd/cipher` | End-to-end CLI. |
| `cipher/internal/sopsx` | The only place sops's unstable internals are imported. |
| `cipher/internal/atomic` | Temp-file-and-rename writes. |

## Errors

Sentinel errors for `errors.Is`:

- `ErrEncode` and `ErrDecode` wrap any encode or decode failure.
- `ErrAlreadyEncrypted` is returned when input already carries sops
  metadata.
- `ErrNotEncrypted` is returned when input is plain.
- `ErrEmpty` is returned when input has no encryptable branches.
- `ErrNoKeyGroups` is returned when the encoder has no key groups.
- `ErrUnsupportedFormat` is returned for formats this library does not
  handle.
- `ErrNoMatchingRule` is returned when a Router cannot match the path.

Walkers treat `ErrAlreadyEncrypted` on encode and `ErrNotEncrypted` on
decode as skip signals, not failures.

## License

See LICENSE.
