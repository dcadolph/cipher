# recipients example

Self-contained. Two age identities (alice, bob). Encrypts to alice, adds bob, removes alice. Confirms which identity can decrypt at each step.

```sh
go run ./examples/recipients
```

The payload ciphertext stays the same across both edits. Only the wrapped data key changes.
