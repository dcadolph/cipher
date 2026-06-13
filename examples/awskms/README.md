# awskms example

Encrypts and decrypts a small YAML using [AWS KMS](https://aws.amazon.com/kms/).

## Setup

1. Authenticate to AWS the same way you would for the `sops` binary (env credentials, shared credentials file, IAM role, [IRSA](https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html), or `AWS_PROFILE`).
2. If you do not already have a KMS key, create one:

   ```sh
   aws kms create-key --description "cipher demo"
   aws kms create-alias --alias-name alias/cipher-demo --target-key-id <KEY_ID>
   ```

3. Grant the principal `kms:Encrypt` and `kms:Decrypt` on the key. The full ARN looks like `arn:aws:kms:REGION:ACCOUNT:key/UUID` or `arn:aws:kms:REGION:ACCOUNT:alias/NAME`.

## Run

```sh
export AWS_KMS_ARNS=arn:aws:kms:us-east-1:111111111111:key/abcd1234-...
go run ./examples/awskms
```

Pass multiple ARNs as a comma-separated list. Optional: `AWS_PROFILE` to pick a named profile.
