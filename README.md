# cipher

Cipher is designed to encrypt and decrypt file data. Currently, it only supports [SOPS](https://github.com/mozilla/sops)
encryption/decryption, but may be enhanced to support other forms of encryption in the future. 

# SOPS

Sops encryption and decryption can be performed per-file using the sops [Encoder](sops/encoder.go) or 
[Decoder](sops/decoder.go), or against all files (on disk) in a given directory using an
[EncodeWalker](sops/encode_walker.go) or [DecodeWalker](sops/decode_walker.go). 

### Age Encryption/Decryption

SOPS age encryption and decryption can be performed using the age [Decoder](sops/age/decoder.go) or 
[DecodeWalker](sops/age/decode_walker.go).

### Other SOPS Encryption/Decryption

Currently, no other SOPS encryption is supported, but [Decoder](sops/decoder.go) and [DecodeWalker](sops/decode_walker.go)
can decrypt SOPS-encrypted data (AWS KMS, GCP KMS, etc.)
