# Security Policy

cipher protects secret files at rest with envelope encryption backed by [SOPS](https://github.com/getsops/sops). This document covers the supported versions, the disclosure process, the threat model, and key handling guidance.

## Supported Versions

Pre-1.0, only the most recent tagged release is supported. Older tags receive no fixes or backports.

| Version | Status |
|---------|--------|
| Latest tag | Active. |
| Older tags | Unsupported. |

## Reporting a Vulnerability

Report privately through [GitHub Security Advisories](https://github.com/dcadolph/cipher/security/advisories/new).

Include:

- Affected version or commit hash.
- A short reproduction.
- Observed impact and any known mitigation.

Acknowledgment target is 72 hours. A coordinated disclosure window is agreed once the report is confirmed. Public disclosure happens after a fix is released, or 90 days from the report, whichever comes first.

Do not open public issues for security reports.

## Threat Model

### What cipher protects

| Asset | Protection |
|-------|------------|
| File contents on disk | Encrypted with a per-file data key wrapped by every configured backend. |
| File contents on a network | Inert ciphertext when paired with HTTPS or other transport security. |
| Recipient changes | Add or remove without re-encrypting the payload. The wrapped data key changes, the bulk payload does not. |
| Plaintext during edit | Materialized only in a private `0700` temp directory in a `0600` file, removed best-effort when the editor exits. |

### What cipher does NOT protect

| Asset | Reason |
|-------|--------|
| Plaintext in memory after decryption | Once `Decode` returns, plaintext lives in the caller's process. Memory hygiene is the caller's responsibility. |
| Decrypted temp files after a crash | `cipher edit` removes the temp dir best-effort. A hard crash leaves the temp file until the OS cleans `/tmp`. |
| Logged plaintext | If the caller logs decrypted contents, cipher cannot help. Use `json:"-"` on secret struct fields and zap encoders that redact. |
| Compromised backend identity | Anyone holding `SOPS_AGE_KEY`, a valid KMS principal, or a Vault token can decrypt every file encrypted to that recipient. Rotate after compromise. |
| Side channels | No constant-time guarantees. Pair with a cloud KMS where a hardware root of trust matters. |
| Compromised dependencies | cipher depends on [SOPS](https://github.com/getsops/sops), [age](https://github.com/FiloSottile/age), and cloud SDKs. A vulnerability in any of those reaches cipher. |
| The host OS, Go runtime, or filesystem | Outside cipher's perimeter. |

### Trust boundaries

| Boundary | Trusted side | Untrusted side |
|----------|--------------|----------------|
| KMS API call | The calling process with valid credentials. | The network in between, assumed HTTPS. |
| Encrypted file | Anyone with read access can copy it. | Without recipient credentials, plaintext stays inaccessible. |
| Editor subprocess | The user's text editor binary. | Other processes on the host that can read `/tmp` while the editor is open. |
| Pre-commit hook | The repo's working tree on a developer machine. | Any shell or editor path that bypasses the hook. |

## Key Handling Guidance

- Generate age identities with `age.GenerateIdentity` or [`age-keygen`](https://github.com/FiloSottile/age). Never derive an age secret from a passphrase or any deterministic input.
- Store the age secret string with `0600` permissions and load it through `SOPS_AGE_KEY_FILE`, or fetch it from a secret manager at startup.
- Prefer cloud KMS in production where IAM and audit logging are first class.
- Rotate the per-file data key with `cipher rotate` after every recipient removal, after personnel changes, and on a periodic schedule.
- Never commit an age secret, a KMS access key, or a Vault token. Install `cipher precommit` to block plaintext leaks at commit time.
- Treat `--allow-orphan` as a one-way door. It removes the last recipient and the file becomes undecryptable.

## Known Limitations

| Limitation | Workaround |
|-----------|------------|
| Plaintext lifetime in memory is not bounded. | Zero buffers in the caller after use. |
| Temp file cleanup is best-effort. | Run `cipher edit` on a host with `tmpfs` for `/tmp`. |
| Recipient identifiers passed via flags are visible to `ps`. | Acceptable. Recipient strings are public-key material, not secret. |
| Logging redaction is the caller's responsibility. | Use the patterns documented in `logger` godoc. |

## Cryptographic Choices

cipher does not implement cryptography. It composes:

- [SOPS](https://github.com/getsops/sops) for envelope encryption and key-group rules.
- [age](https://github.com/FiloSottile/age) for X25519 plus ChaCha20-Poly1305.
- AWS, GCP, Azure, and Vault SDKs for managed-key envelope wrapping.

Algorithm parameters follow the defaults of each backend. Propose algorithm upgrades through the regular issue tracker, not this disclosure path.

## Changes to This Policy

Track this file in git. Material changes get a SECURITY.md commit and a corresponding entry in the release notes for that tag.
