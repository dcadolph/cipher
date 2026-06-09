# cipher CLI

Every verb, every flag, every shape.

The CLI ships in `cmd/cipher`. Install with:

```sh
go install github.com/dcadolph/cipher/cmd/cipher@latest
```

| Verb | Purpose |
|------|---------|
| [encrypt](#encrypt) | Encrypt a single file. |
| [decrypt](#decrypt) | Decrypt a single file. |
| [edit](#edit) | Decrypt, open in your text editor, re-encrypt. |
| [rotate](#rotate) | Generate a fresh data key for a file. |
| [walk](#walk) | Apply encrypt, decrypt, or rotate across a directory. |
| [add-recipient](#add-recipient) | Add recipients without re-encrypting the payload. |
| [remove-recipient](#remove-recipient) | Drop recipients by identifier. |
| [recipients](#recipients) | List, drift, or orphans audit. |
| [info](#info) | Print [SOPS](https://github.com/getsops/sops) metadata as JSON. |
| [fix](#fix) | Encrypt plaintext files matching `.sops.yaml`. |
| [config](#config) | Validate `.sops.yaml`. |
| [precommit](#precommit) | Reject staged plaintext that should be encrypted. |
| [demo](#demo) | Open in-browser cinematic explainers. |
| [version](#version) | Print the cipher version. |

## Common flags

These flags apply to every verb that needs recipients or that tunes encoding.

### Recipient selection

| Flag | Description |
|------|-------------|
| `--age` | Comma-separated age recipients (X25519, hybrid, plugin, or SSH form). |
| `--kms` | Comma-separated AWS KMS key ARNs. |
| `--gcp-kms` | Comma-separated GCP KMS resource IDs. |
| `--vault-uri` | Comma-separated Vault Transit URIs. |
| `--azure-keyvault` | Comma-separated Azure Key Vault key URLs. |
| `--pgp` | Comma-separated GPG fingerprints. |
| `--config` | Path to `.sops.yaml` or directory containing it. When set, routes recipients per path via the project's [SOPS](https://github.com/getsops/sops) rules. |
| `--kms-context` | AWS KMS encryption context entry `key=value`. Repeatable. |
| `--aws-profile` | AWS shared-credentials profile name for KMS calls. |

### Encoder tuning

| Flag | Description |
|------|-------------|
| `--encrypted-regex` | Encrypt only keys whose name matches this regex. |
| `--unencrypted-regex` | Never encrypt keys whose name matches this regex. |
| `--encrypted-suffix` | Encrypt only keys whose name ends with this suffix. |
| `--unencrypted-suffix` | Never encrypt keys whose name ends with this suffix. |
| `--mac-only-encrypted` | Compute the MAC over encrypted leaves only. |
| `--shamir-threshold` | Number of key groups required to recover the data key. |

### I/O

| Flag | Description |
|------|-------------|
| `-i`, `--in-place` | Write back to PATH atomically. |
| `-o`, `--output FILE` | Write to FILE instead of stdout. |
| `PATH == "-"` | Read from stdin and write to stdout. |

### Identity sources

Decryption reads identity from the same environment the [SOPS](https://github.com/getsops/sops) binary uses. The first matching source for the backend wins.

| Backend | Source |
|---------|--------|
| [age](https://github.com/FiloSottile/age) | `SOPS_AGE_KEY`, `SOPS_AGE_KEY_FILE`, `SOPS_AGE_SSH_PRIVATE_KEY_FILE`. |
| [AWS KMS](https://aws.amazon.com/kms/) | Default AWS SDK credential chain (env, `~/.aws/`, IAM role, [IRSA](https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html)). |
| [GCP KMS](https://cloud.google.com/kms) | Google application-default credentials. |
| [Vault Transit](https://developer.hashicorp.com/vault/docs/secrets/transit) | `VAULT_TOKEN`, `VAULT_ADDR`, `~/.vault-token`. |
| [Azure Key Vault](https://learn.microsoft.com/azure/key-vault/) | Azure default credential chain (env, managed identity, az CLI). |
| [PGP](https://www.gnupg.org/) | `gpg` binary on `PATH`. |

---

## encrypt

Encrypt a single file.

```sh
cipher encrypt PATH [recipient flags] [-i | -o FILE]
```

Examples:

```sh
cipher encrypt secrets.yaml --age age1qyqsz... -i
cipher encrypt - --age age1qyqsz... < plain.yaml > encrypted.yaml
cipher encrypt secrets.yaml --kms arn:aws:kms:... --kms-context env=prod
```

## decrypt

Decrypt a single file. Identity comes from the same environment the [SOPS](https://github.com/getsops/sops) binary reads. See [Identity sources](#identity-sources) below.

```sh
cipher decrypt PATH [-i | -o FILE]
```

Examples:

```sh
cipher decrypt secrets.yaml
cipher decrypt secrets.yaml -o plain.yaml
cipher decrypt - < encrypted.yaml > plain.yaml
```

## edit

Decrypt PATH to a private temp file, open your text editor on it, re-encrypt and write back atomically.

```sh
cipher edit PATH [recipient flags] [--cmd EDITOR] [--backup-suffix SUFFIX]
```

| Flag | Description |
|------|-------------|
| `--cmd` | Editor command. Defaults to `$EDITOR`, then `$VISUAL`, then `vi`. |
| `--backup-suffix` | Copy the encrypted original to `<path><suffix>` before overwriting. |

Examples:

```sh
cipher edit secrets.yaml --age age1qyqsz...
EDITOR="code --wait" cipher edit secrets.yaml --age age1qyqsz...
cipher edit secrets.yaml --age age1qyqsz... --backup-suffix .bak
```

Security model: plaintext is materialized only in a fresh `0700` temp directory in a `0600` file, removed best-effort when the editor exits. The editor command runs through `/bin/sh`. Do not pass untrusted `$EDITOR` values.

## rotate

Decrypt PATH, generate a fresh data key, re-encrypt with the recipients implied by the recipient flags. The plaintext does not change. The ciphertext does.

```sh
cipher rotate PATH... [recipient flags] [-i | -o FILE]
```

Examples:

```sh
cipher rotate secrets.yaml --age age1qyqsz... -i
cipher rotate secrets.yaml backup.yaml --config .sops.yaml -i
```

## walk

Apply an operation to every matching file under ROOT.

```sh
cipher walk encrypt ROOT [recipient flags] [walk flags]
cipher walk decrypt ROOT [walk flags]
cipher walk rotate ROOT [recipient flags] [walk flags] [--older-than DUR]
```

### Walk flags

| Flag | Description |
|------|-------------|
| `--ext` | Comma-separated extensions to match (default `yaml,yml,json`). |
| `--regex` | Regular expression matched against full path. Overrides `--ext`. |
| `--parallel N` | Maximum concurrent files (default 1). |
| `--backup-suffix` | Write each original to `<path><suffix>` before overwriting. |
| `--older-than` | (rotate only) Skip files whose [SOPS](https://github.com/getsops/sops) `LastModified` is newer than DUR. Accepts `90d`, `720h`, `30m`. |

Examples:

```sh
cipher walk encrypt ./secrets --age age1qyqsz... --parallel 8
cipher walk decrypt ./secrets --regex 'secrets/(prod|stage)/.*\.yaml$'
cipher walk rotate ./secrets --config .sops.yaml --older-than 90d
```

## add-recipient

Add recipients to an encrypted file without re-encrypting the payload. The wrapped data key changes. The ciphertext does not.

```sh
cipher add-recipient PATH [recipient flags] [--as-groups] [-i | -o FILE]
```

| Flag | Description |
|------|-------------|
| `--as-groups` | Append new recipients as additional key groups instead of flattening into the first group. Use with Shamir. |

Examples:

```sh
cipher add-recipient secrets.yaml --age age1bob... -i
cipher add-recipient secrets.yaml --kms arn:aws:kms:... --as-groups -i
```

## remove-recipient

Drop recipients from an encrypted file by identifier. Refuses to leave the file with zero recipients unless `--allow-orphan` is set.

```sh
cipher remove-recipient PATH IDENTIFIER [IDENTIFIER...] [--allow-orphan] [-i | -o FILE]
```

| Flag | Description |
|------|-------------|
| `--allow-orphan` | Permit removing the last recipient. The file becomes undecryptable forever. |

Examples:

```sh
cipher remove-recipient secrets.yaml age1bob... -i
cipher remove-recipient secrets.yaml arn:aws:kms:... arn:aws:kms:... -i
```

## recipients

Inspect and audit recipient sets across encrypted files.

```sh
cipher recipients list PATH [--pretty]
cipher recipients drift ROOT [--config PATH] [--pretty]
cipher recipients orphans ROOT [--config PATH] [--pretty]
```

| Subcommand | Description |
|------------|-------------|
| `list` | Print the recipients recorded in PATH as JSON. |
| `drift` | Compare file recipients against `.sops.yaml` rule. Report mismatches. |
| `orphans` | Report files with recipients the rule no longer expects. |

| Flag | Description |
|------|-------------|
| `--config` | `.sops.yaml` location. Default searches upward from cwd. |
| `--pretty` | Indent JSON output. |

Examples:

```sh
cipher recipients list secrets.yaml --pretty
cipher recipients drift ./secrets --config .sops.yaml
cipher recipients orphans ./secrets > orphans.json
```

## info

Print the metadata of a [SOPS](https://github.com/getsops/sops)-encrypted file as JSON. Does not decrypt.

```sh
cipher info PATH [--pretty]
```

Example:

```sh
cipher info secrets.yaml --pretty
```

## fix

Walk ROOT, find files that match a `.sops.yaml` creation rule but are still plaintext, and encrypt them in place. Repairs a tree where a rule was added after plaintext files were committed.

```sh
cipher fix ROOT [--config PATH] [--backup-suffix SUFFIX] [--parallel N]
```

Example:

```sh
cipher fix ./secrets --config .sops.yaml --parallel 8
```

## config

Validate `.sops.yaml`: regex syntax, recipient shapes, key-group reachability.

```sh
cipher config check [PATH]
```

Example:

```sh
cipher config check .sops.yaml
```

Exits non-zero with a list of problems if any are found.

## precommit

Reject any staged file that should be [SOPS](https://github.com/getsops/sops)-encrypted but is not. Designed for a git pre-commit hook.

```sh
cipher precommit [PATH...] [--config PATH] [--max-staged-bytes N]
```

With no PATH arguments, scans `git diff --cached`. Otherwise scans the supplied paths on disk.

| Flag | Description |
|------|-------------|
| `--config` | `.sops.yaml` location. Default searches upward from cwd. |
| `--max-staged-bytes` | Reject staged blobs larger than N bytes (default 64 MiB). 0 disables the cap. |

Install as a hook:

```sh
#!/usr/bin/env bash
# .git/hooks/pre-commit
exec cipher precommit
```

With the [pre-commit](https://pre-commit.com/) framework, add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: local
    hooks:
      - id: cipher
        name: cipher precommit
        entry: cipher precommit
        language: system
        stages: [commit]
        pass_filenames: false
```

## demo

Open in-browser cinematic explainers.

```sh
cipher demo [--addr ADDR] [--no-browser] [--explainer SLUG]
```

| Flag | Description |
|------|-------------|
| `--addr` | Listen address (default `127.0.0.1:0`, ephemeral port). |
| `--no-browser` | Print the URL instead of opening the browser. |
| `--explainer` | Jump to a specific cinematic slug. |

Available slugs:

| Slug | Length | Covers |
|------|--------|--------|
| `intro` | ~60 s | What cipher is for first-time visitors. |
| `how-it-works` | ~80 s | Envelope encryption walked end to end. |
| `tour` | ~90 s | Hero overview of every feature. |
| `walk` | ~60 s | Encrypting a directory in parallel. |
| `recipients` | ~60 s | Add and remove without re-encrypting. |
| `precommit` | ~60 s | Blocking plaintext at commit time with a [git pre-commit hook](https://git-scm.com/docs/githooks). |

Examples:

```sh
cipher demo
cipher demo --explainer intro
cipher demo --addr 127.0.0.1:8765 --no-browser
```

## version

Print the cipher version.

```sh
cipher version
```
