# cipher examples

Runnable Go programs for every backend and most cross-cutting features. Each example is `go run`-able from the repo root.

```sh
go run ./examples/age
go run ./examples/walk
go run ./examples/httpmw
```

## Self-contained

These run with no external credentials. They generate a throwaway age identity and use the local filesystem.

| Example | Covers |
|---------|--------|
| [age](age/) | Generate identity, encrypt, decrypt. |
| [walk](walk/) | Parallel directory encrypt. |
| [rotate](rotate/) | Rotate the per-file data key. |
| [recipients](recipients/) | Add and remove recipients without re-encrypting. |
| [merge](merge/) | Combine providers, threshold-of-N with Shamir. |
| [httpmw](httpmw/) | Encrypt response and decrypt request bodies. |
| [otel](otel/) | Wrap encoder, decoder, and provider with OpenTelemetry traces. |

## Cloud backends

These build cleanly but need real credentials to run. Each example's README documents the setup.

| Example | Requires |
|---------|----------|
| [awskms](awskms/) | AWS credentials and a KMS key ARN. |
| [gcpkms](gcpkms/) | Google application-default credentials and a key resource ID. |
| [vault](vault/) | A Vault Transit URI and `VAULT_TOKEN` plus `VAULT_ADDR`. |
| [azkv](azkv/) | Azure default credentials and a Key Vault key URL. |
| [pgp](pgp/) | A `gpg` keyring with a usable secret key and the fingerprint of a recipient. |

## Build all

```sh
go build ./examples/...
```
