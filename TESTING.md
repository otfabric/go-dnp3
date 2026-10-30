# Testing

How go-dnp3 is tested. What each tier covers per feature is in
[docs/FEATURE-STATUS.md](docs/FEATURE-STATUS.md); which test to write for a
change is in [CONTRIBUTING.md](CONTRIBUTING.md#tests).

## Tiers

| Tier | Command | Needs | Runs in CI |
|---|---|---|---|
| Unit and component tests, with the race detector | `make test` | Go | `CI`, Go 1.23 to 1.26, on every push and pull request |
| End-to-end: go-dnp3's master against its outstation over loopback, including chaos and stress (`e2e/`) | `make e2e` | Go | part of `make test` |
| Coverage gate | `make coverage-check` | Go | `CI` (`coverage-min: "90"`) |
| Fuzzing | `make fuzz` | Go | `CI`, 10 s per target |
| Benchmarks of the codecs (`link`, `transport`, `app`) | `make bench` | Go | no |
| Examples: each self-contained one must exit successfully | `make examples` | Go | `CI` |
| Generated files against `app/catalog.json` | `make generate-check` | Go | `CI` |
| Cross-compilation without cgo: linux/amd64, arm64, arm; darwin/arm64; windows/amd64 | `make cross` | Go | no |
| Interop with independent stacks, both roles | `make interop` | Go, Docker | `Interop`, on every push and pull request |
| DNP Users Group IED certification procedures with dnp3c | `make conformance` | Go, Docker | `Conformance`, on every push and pull request |
| Catalog against the upstream object definitions | `make upstream-watch` | network | `Upstream watch`, weekly |

`make check` is the local gate. It runs `make coverage`, which reports
coverage without failing on it; run `make coverage-check` for the gate. It
does not run `make fuzz`, `make e2e` on its own (`make test` includes the
suite), `make interop` or `make conformance`.

All tests run on Linux in CI. No tier uses DNP3 hardware or a real serial
line: serial is tested over byte streams, and in the interop suite over a
pseudo-terminal bridged to TCP.

## Chaos and stress

`e2e/chaos_test.go` sends every kind of request through a proxy that
corrupts, splits and delays octets and kills connections, with and without
Secure Authentication. It checks that no data appears that was not sent, that
no control runs more often than it was sent, and that the session recovers
once the faults stop. Each run logs its random seed (`seed <n>`). `go test
-short` shortens it from 3 s to 1 s per subtest. `e2e/stress_test.go` covers
concurrent requests, many masters, reconnects, rapid open and close, and
cancellation.

## Interop

The suite in `interop/` is behind the `interop` build tag, and consumes the
images of [otfabric/dnp3-interop](https://github.com/otfabric/dnp3-interop)
at the release pinned in the Makefile, `interop/harness.go` and
`.github/workflows/interop.yml`. [README.md](README.md#interop-tests) explains
how the images are obtained; the peers and results are in
[INTEROPERABILITY.md](INTEROPERABILITY.md#interop-coverage).

| Variable | Effect |
|---|---|
| `DNP3_INTEROP_STEPFUNC_IMAGE`, `DNP3_INTEROP_OPENDNP3_IMAGE`, `DNP3_INTEROP_DSCSYSTEMS_IMAGE`, `DNP3_INTEROP_DNP3PY_IMAGE` | Use another image of that peer |
| `DNP3_INTEROP_ADAPTERS` | Comma-separated subset of `stepfunc`, `opendnp3`, `dscsystems`, `dnp3py` |

There is no `*_REQUIRE_*` switch, and none is needed for Docker itself:
without Docker or an image the suite fails, it does not skip. A subtest skips
only when a peer's image declares that it lacks the role or feature, or (one
frozen counter case in `interop/v13_test.go`) when the test's precondition
does not hold.

## Conformance

`make conformance` runs dnp3c against the test outstation in
[internal/cmd/conformance](internal/cmd/conformance), whose README describes
the setup and how to run a single procedure. `make conformance` exits
non-zero when a procedure fails or is excluded. Reports are written to
`bin/conformance/results/<revision>/L<level>/report.html`. This is not a
certification ([LIMITATIONS.md](LIMITATIONS.md#conformance-and-certification)).

## Coverage policy

The floor is 90 %, set by `coverage-min` in
[ci.yml](.github/workflows/ci.yml) and `COVER_MIN` in the Makefile.
`make coverpkg-check` keeps CI's `coverpkg` equal to the Makefile's
`COVER_PKGS`. Coverage is measured over all library packages at once, so the
e2e suite and the client and server tests count for each other's packages.

Left out of `COVER_PKGS`, and why:

| Package | Reason |
|---|---|
| `examples/...` | Programs, run by `make examples` |
| `internal/cmd/...` | Tools: the catalog generator, the upstream watch and the conformance outstation |
| `e2e` | Holds only tests |
| `interop` | Behind a build tag; holds the harness and tests |

## Fuzzing

Targets: `FuzzDecode` and `FuzzReader` (`link`), `FuzzReassembler`
(`transport`), `FuzzDecode` (`app`), `FuzzOutstation` and `FuzzPack`
(`server`). `make fuzz` runs each for `FUZZTIME` (default 30s). A new target
must be added to the `fuzz` recipe by name.

When a target fails, Go writes the input to `testdata/fuzz/<Target>/` in the
package. To keep it as a regression test, fix the cause and commit that file;
`go test` then replays it on every run. Reproduce one input with
`go test -run '<Target>/<file>' ./<package>`.
