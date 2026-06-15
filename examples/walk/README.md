# walk example

Self-contained. Seeds a small in-memory directory of YAML and JSON files, walks it with eight workers, encrypts every match using [age](https://github.com/FiloSottile/age), and reports the result.

```sh
go run ./examples/walk
```

No credentials required.
