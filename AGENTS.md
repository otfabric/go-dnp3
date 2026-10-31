# AGENTS.md — go-dnp3

## What this is

Pure Go DNP3 (IEEE 1815-2012) master and outstation: link, transport and application layers, object library, file transfer, Secure Authentication v5. No cgo, no dependencies outside the standard library. Profile: **protocol-library**. The library is on v1: the exported API is semver-binding. Not certified (LIMITATIONS.md).

## Organisation standards

This repository follows **otfabric/engineering policy 1.2**, profile **protocol-library** (`.otfabric/policy.yaml`, mode `enforce`). Where this file and the organisation standards disagree, this file wins here — say so in your report.

## Where the truth lives

| Question | Source |
|---|---|
| Wire behaviour | IEEE 1815-2012 |
| Objects | `app/catalog.json` (generates the object table and OBJECTS.md) |
| What is implemented, clause by clause, and verified | INTEROPERABILITY.md, LIMITATIONS.md |
| Errors | ERRORS.md |
| Release history | RELEASE.md (`## vX.Y.Z` … `---`) |

## Hard rules

1. Never lower the coverage minimum (`coverage-min` 90 in CI), add lint suppressions, or skip or delete tests to make CI pass.
2. Never invent protocol semantics; cite the clause.
3. Never claim conformance or interoperability beyond the evidence in INTEROPERABILITY.md. The dnp3c run is not a certification.
4. No incidental breaking changes to exported API; this library stays on v1.
5. No dependencies outside the standard library.
6. Generated files change through `app/catalog.json` and `make generate`.

## Commands

| When you change… | Run |
|---|---|
| anything | `make check` |
| a decoder or the outstation | `make fuzz` (a new decoder needs a fuzz target) |
| interop-relevant behaviour | `make interop` (Docker) |
| outstation behaviour | `make conformance` (Docker) |

## Definition of Done

`make check` green; tests for new behaviour including error paths; API.md, ERRORS.md, INTEROPERABILITY.md and LIMITATIONS.md updated; RELEASE.md section for user-visible changes; failing or skipped steps reported.

## Git and releases

Branches and PRs. Do not push to `main`, tag or run the Release workflow unless the maintainer asks in the session.
