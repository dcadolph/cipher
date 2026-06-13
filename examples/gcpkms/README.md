# gcpkms example

Encrypts and decrypts a small YAML using [GCP KMS](https://cloud.google.com/kms).

## Setup

1. Authenticate with Google application-default credentials: `gcloud auth application-default login`, set `GOOGLE_APPLICATION_CREDENTIALS` to a service-account key path, or run on a host with Workload Identity.
2. If you do not already have a key, create one:

   ```sh
   gcloud kms keyrings create cipher-demo --location global
   gcloud kms keys create demo-key \
     --keyring cipher-demo --location global \
     --purpose encryption
   ```

3. Grant the principal `roles/cloudkms.cryptoKeyEncrypterDecrypter` on the key. The resource ID looks like `projects/PROJ/locations/LOC/keyRings/RING/cryptoKeys/KEY`.

## Run

```sh
export GCP_KMS_IDS=projects/PROJ/locations/LOC/keyRings/RING/cryptoKeys/KEY
go run ./examples/gcpkms
```

Pass multiple resource IDs as a comma-separated list.
