# rotate example

Self-contained. Encrypts a file, then calls `cipher.Rotate` to produce a fresh data key. Confirms the ciphertext changed and the plaintext did not.

```sh
go run ./examples/rotate
```

No credentials required.
