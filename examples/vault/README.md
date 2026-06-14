# vault example

Encrypts and decrypts a small YAML using [HashiCorp Vault Transit](https://developer.hashicorp.com/vault/docs/secrets/transit).

## Setup

1. Make sure Vault is reachable and unsealed.
2. Mount the Transit engine and create a key if you have not already:

   ```sh
   vault secrets enable transit
   vault write -f transit/keys/cipher-demo
   ```

3. Issue a token with a policy that grants `update` on `transit/encrypt/cipher-demo` and `transit/decrypt/cipher-demo`. Export the token plus `VAULT_ADDR`.

## Run

```sh
export VAULT_ADDR=https://vault.example.com
export VAULT_TOKEN=hvs.example
export VAULT_TRANSIT_URIS=$VAULT_ADDR/v1/transit/keys/cipher-demo
go run ./examples/vault
```

Pass multiple URIs as a comma-separated list.
