# Testing

How go-dnp3 is tested. What each tier covers per feature is in
[docs/FEATURE-STATUS.md](docs/FEATURE-STATUS.md); which test to write for a
change is in [CONTRIBUTING.md](CONTRIBUTING.md#tests).

## Tiers

| Tier | Command | Needs | Runs in CI |
|---|---|---|---|
| Unit and component tests, with the race detector | `make test` | Go | `CI`, Go 1.26 and 1.27, on every push and pull request |
| End-to-end: go-dnp3's master against its outstation over loopback, including chaos and stress (`e2e/`) | `make e2e` | Go | part of `make test` |
| Coverage gate | `make coverage-check` | Go | `CI` (`coverage-min: "90"`) |
| Per-package coverage floor | `make coverage-pkg-check` | Go | `CI` (`Per-package coverage`) |
| Fuzzing | `make fuzz` | Go | `CI`, 10 s per target |
| Benchmarks of the codecs (`link`, `transport`, `app`) | `make bench` | Go | no |
| Examples: each self-contained one must exit successfully | `make examples` | Go | `CI` |
| Generated files against `app/catalog.json` | `make generate-check` | Go | `CI` |
| Cross-compilation without cgo: linux/amd64, arm64, arm; darwin/arm64; windows/amd64 | `make cross` | Go | no |
| Interop with independent stacks, both roles | `make interop` | Go, Docker | `Interop`, on every push and pull request |
| DNP Users Group IED certification procedures with dnp3c | `make conformance` | Go, Docker | `Conformance`, on every push and pull request |
| Catalog against the upstream object definitions | `make upstream-watch` | network | `Upstream watch`, weekly |
| Recorded traffic: decode, encode, Wireshark and conformance-log oracles, client and server replay ([testdata/captures](testdata/captures/README.md)) | part of `make test`; `make captures-verify` checks the SHA256 | Go | `CI` (tests), `Captures` (SHA256) |

`make check` is the local gate. It runs `make coverage-pkg-check`, which fails
when a package is below `COVER_PKG_MIN`; run `make coverage-check` for the
gate on the total. It does not run `make fuzz`, `make e2e` on its own (`make test` includes the
suite), `make interop` or `make conformance`.

All tests run on Linux in CI. No tier uses DNP3 hardware or a real serial
line, and the recorded traffic is not from identified hardware: serial is tested over byte streams, and in the interop suite over a
pseudo-terminal bridged to TCP.

## Spec tests

Tests named `TestSpec<clause>_<what>` (for example
`TestSpecTable8_1`, `TestSpec13_2_3_3_SecondConnectionRejected`)
check one requirement of IEEE 1815-2012 each; their doc comment cites the
clause, table or example and the printed page. They live in `spec_*_test.go`
files next to the code (`link`, `transport`, `internal/channel`, `app`,
`secauth`, `client`, `server`) and, where master and outstation both take
part, in `e2e/spec_*_test.go`. The standard is not in the repository: it is
copyrighted, so the tests carry clause references, not its text. A test
that pins behaviour the standard leaves open says so.

## Recorded traffic

[testdata/captures](testdata/captures/README.md) holds 182 network
captures of other DNP3 software, committed byte-identical (8.4 MB, no file
over 50 MB, so no extended corpus): the ITI ICS-Security-Tools DNP3
captures, including 140 runs of a conformance runner against the opendnp3
3.0 outstation with the runner's logs, the Zeek DNP3 test traces and the
igbe attack data set. They are software-generated or of unknown origin
(evidence classes C and D), not traffic of identified hardware.

`internal/capture` reads pcap and pcapng (Ethernet, BSD loopback; IPv4; TCP
reassembled per direction, UDP), runs `link.Reader`, the transport
`Reassembler` and `app.Decode` over every conversation and checks: the
manifest and SHA256SUMS; that every decoded frame and fragment encodes back
to its octets; the decoding against Wireshark's (`testdata/captures/tshark`,
`make captures-oracle`) and against the conformance runner's log; that every
error is classified; `coverage.json` (`make captures-report`); the fuzz
seeds taken from the captures (`make captures-seeds`). `client` replays the
recorded requests and procedures against the recorded responses; `server`
sends the recorded requests, and the link-layer octets of the link
procedures, to the outstation and compares its answers with the recorded
ones. The comparison rules and the classified differences are in the
captures README.

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
| `DNP3_INTEROP_OPENDNP3_IMAGE`, `DNP3_INTEROP_DSCSYSTEMS_IMAGE`, `DNP3_INTEROP_DNP3PY_IMAGE`, `DNP3_INTEROP_CBSIGMA_IMAGE`, `DNP3_INTEROP_NFMDNP3_IMAGE` | Use another image of that peer |
| `DNP3_INTEROP_ADAPTERS` | Comma-separated subset of `opendnp3`, `dscsystems`, `dnp3py`, `cbsigma`, `nfmdnp3` |

| `DNP3_REQUIRE_INTEROP=1` | Fail instead of skip when Docker is not available. `make interop` and the `Interop` workflow set it |

Run with plain `go test -tags=interop` and without Docker, a test skips and
says so. An image that cannot be run fails the test in either case. Otherwise a subtest skips
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
Each package has a floor of its own, `COVER_PKG_MIN` (90 %), checked by
`make coverage-pkg-check` on the same profile.

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
(`server`), `FuzzMaster` (`client`: the master against an outstation that
answers every request with the fuzz input, with Secure Authentication
configured) and `FuzzKeyUnwrap` (`secauth`: session key change data). `make fuzz` runs each for `FUZZTIME` (default 30s). A new target
must be added to the `fuzz` recipe by name.

The corpora hold seeds taken from the recorded traffic
(`capture-<file>-<frame>`, written by `make captures-seeds`): one per shape
of fragment, every fragment the decoder refuses, link frames and the octets
around framing errors.

When a target fails, Go writes the input to `testdata/fuzz/<Target>/` in the
package. To keep it as a regression test, fix the cause and commit that file;
`go test` then replays it on every run. Reproduce one input with
`go test -run '<Target>/<file>' ./<package>`.
