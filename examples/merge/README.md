# merge example

Self-contained. Three age identities. Demonstrates three composition strategies:

| Helper | Result |
|--------|--------|
| `MergeProviders` | One key group, every identity decrypts. |
| `ChainKeyProviders` | One key group per identity, any group decrypts. |
| `NewShamirRule(_, threshold, ...)` | Threshold-of-N key groups must decrypt. |

```sh
go run ./examples/merge
```
