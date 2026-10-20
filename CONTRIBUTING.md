# Contributing to go-dnp3

Thank you for your interest in contributing to `go-dnp3`! This document covers the guidelines for contributing.

## Getting Started

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```sh
   git clone git@github.com:<your-username>/go-dnp3.git
   cd go-dnp3
   ```
3. Create a feature branch:
   ```sh
   git checkout -b feature/my-change
   ```

## Development Setup

### Prerequisites

- Go 1.23+ (see [go.mod](go.mod)); the code must build and pass on Go 1.23, so do not use newer language or standard-library features
- [staticcheck](https://staticcheck.dev/), [golangci-lint](https://golangci-lint.run/) and [govulncheck](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck) for the checks
- No hardware and no external simulator: tests run master and outstation against each other and against scripted peers over loopback
- Docker, for the interop tests only

### Build & Test

```sh
# Run all checks (format, lint, vet, vulnerability scan, race tests, coverage, examples)
make check

# Run the tests with the race detector
make test

# Run the codec and outstation fuzz targets (FUZZTIME=30s by default)
make fuzz

# Run the codec benchmarks
make bench

# Regenerate the object table, Measurements' points and OBJECTS.md from app/catalog.json
make generate

# Compare the catalog with stepfunc dnp3 and DSC go-dnp3, and look for a new dnp3-interop release
make upstream-watch

# Run the interop tests against the dnp3-interop reference images (needs Docker)
make interop

# Build the examples into ./bin
make build
```

## Guidelines

### Code

- **No dependencies** outside the standard library. The module's value for users in regulated environments depends on it
- **Codecs stay pure**: `link`, `transport` and `app` do no I/O beyond `link.Reader` over an `io.Reader` and keep no state across fragments
- **Every exported symbol is documented**, with the standard's terms; comments end with a period (golangci-lint's `godot`)
- **Errors** are sentinels wrapped with detail, or typed errors for answers of the peer; see [ERRORS.md](ERRORS.md). Never return a bare `errors.New` from a public function
- **Concurrency**: say in the comment which goroutine owns a field. Prefer one goroutine owning state over locks around it, as the channel, the association and the client do
- **Logging** goes through `internal/logx` with a constant message and fields; see [OBSERVABILITY.md](OBSERVABILITY.md)
- Format with `make fmt`: the gofmt of the Go version in go.mod, which CI uses
- **The objects are a catalog**: `app/catalog.json` names every group and variation with its codec family, numeric type, flags, time, event, size and whether it is a point. `app/registry_table.go`, `client/points_table.go` and `OBJECTS.md` are generated from it (`internal/cmd/gencatalog`): change the catalog and run `make generate`, never the generated files. `make check` and CI fail when they are out of date. `TestCatalog` checks each entry against the codec, so a new family still needs its code in `app/registry.go`

### Upstream watch

A weekly workflow (`.github/workflows/upstream-watch.yml`) runs `internal/cmd/upstreamwatch`. It reports, in one issue labelled `upstream-watch`:

- commits to the object definitions of stepfunc dnp3 or DSC go-dnp3 since the commit recorded as reviewed in `.github/upstream.json`;
- an object they define with a fixed layout whose size differs from `app/catalog.json`, or that the catalog lacks;
- a dnp3-interop release newer than the one the interop harness pins.

The comparison is of facts only (group, variation, size); nothing of those projects is copied. After a review, update the catalog if the standard's objects are concerned and set `reviewed` to the commit the report names; the issue closes on the next run with nothing to report.

### Tests

Every change comes with tests at the level it touches:

| Change | Test |
|--------|------|
| A codec | Unit tests with known vectors, the round trip test covers new variations by itself; run `make fuzz` |
| The link layer procedures | A frame-by-frame test with a raw peer in `internal/channel` |
| An outstation behaviour | A scripted-master test in `server/conformance_test.go` with exact requests |
| A master behaviour | A test in `client` against a real outstation or a silent peer |
| A feature across both | An end-to-end test in `e2e` |
| Behaviour the references also have | An interop test in `interop` |

Tests must pass with `-race`, repeatedly: run new ones with `-count=10`. A
test that waits uses a deadline and a condition, never a fixed sleep for
something to happen.

### Interop

The interop tests consume the images of
[otfabric/dnp3-interop](https://github.com/otfabric/dnp3-interop). This
repository holds no reference code. A reference that deviates from the
fixture's behaviour is recorded in dnp3-interop's `tests/known-bugs.tsv`
and mirrored in `interop/harness.go`'s `knownBugs`, so that the test checks
the behaviour and logs the deviation.

## Pull Requests

- One logical change per pull request, with a description of what and why
- `make check` passes; `make interop` passes for changes to procedures
- Update [RELEASE.md](RELEASE.md) under the unreleased version, and the docs the change affects ([API.md](API.md), [INTEROPERABILITY.md](INTEROPERABILITY.md), ...)

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
