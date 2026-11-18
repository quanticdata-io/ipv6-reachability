# Contributing

Thanks for helping improve ipv6-reachability.

## Development

Requirements: Go 1.22 or newer.

```sh
go build ./...
go vet ./...
go test ./...
gofmt -l .                 # must print nothing
```

CI runs the tests on Linux, macOS and Windows with Go 1.22 and the latest Go, the race detector on Linux and macOS, and `golangci-lint` v2.6 (with Go 1.25) using `.golangci.yml`.

## Tests never use the network

Tests use a fake resolver, made-up `.test` hosts served by in-process HTTP servers, a fake DoH server and a fake echo proxy, all on 127.0.0.1. Use documentation addresses (192.0.2.0/24, 2001:db8::/32) in fixtures. Do not add tests that reach the internet or a real proxy.

## Ground rules

- Keep the binary dependency-free (standard library only) unless there is a strong reason; discuss it in an issue first.
- Report what was observed. When something cannot be checked (DNS failed, the chain stopped), say so in the result instead of guessing a verdict.
- Never print a proxy password: use `url.Redacted()`.
- Keep the JSON fields and CSV columns backwards compatible: add, do not rename.
- Update `CHANGELOG.md` under "Unreleased".
