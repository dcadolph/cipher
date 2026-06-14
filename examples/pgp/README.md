# pgp example

Encrypts and decrypts a small YAML using [GnuPG](https://www.gnupg.org/).

## Setup

1. Install `gpg` and make sure it is on `PATH`.
2. If you do not already have a key, generate one:

   ```sh
   gpg --quick-generate-key 'cipher demo <cipher-demo@example.invalid>' rsa4096 encrypt 1y
   ```

3. Find the fingerprint:

   ```sh
   gpg --list-secret-keys --with-colons | awk -F: '$1 == "fpr" { print $10; exit }'
   ```

   It is 40 hex characters with no spaces, for example `1234ABCD5678EF901234ABCD5678EF901234ABCD`.

## Run

```sh
export PGP_FINGERPRINTS=1234ABCD5678EF901234ABCD5678EF901234ABCD
go run ./examples/pgp
```

Pass multiple fingerprints as a comma-separated list.
