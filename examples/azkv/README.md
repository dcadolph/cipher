# azkv example

Encrypts and decrypts a small YAML using [Azure Key Vault](https://learn.microsoft.com/azure/key-vault/).

## Setup

1. Authenticate with the default Azure credential chain (`AZURE_CLIENT_ID` env triple, managed identity, or `az login`).
2. If you do not already have a Key Vault and key, create them:

   ```sh
   az keyvault create -n cipher-demo -g my-rg --enable-rbac-authorization
   az keyvault key create --vault-name cipher-demo -n demo-key --protection software --ops wrapKey unwrapKey
   ```

3. Grant the principal the `Key Vault Crypto User` role (or `keys/wrapKey` and `keys/unwrapKey` via access policy). The full key URL appears in the create output and looks like `https://cipher-demo.vault.azure.net/keys/demo-key/<VERSION>`.

## Run

```sh
export AZURE_KV_URLS=https://my-vault.vault.azure.net/keys/cipher-demo/abcd1234
go run ./examples/azkv
```

Pass multiple URLs as a comma-separated list. Include the version segment for stable wrapping.
