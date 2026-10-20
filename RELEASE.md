# go-dnp3 Releases

## v0.1.1

**Date:** 2026-10-20
**Previous release:** v0.1.0

## Summary

A fix for confirmations lost when the peer closes the connection right
after sending them. No API change.

## Changes

### Fixed

- **Fragments received just before the peer closed were dropped.** When a connection ended, a session could stop before handing over fragments it had already received and queued. An outstation could then miss the confirmation of a response from a master that confirms and hangs up at once, and report the same events again on the next connection. The interop suite caught it intermittently against the stepfunc master. Queued fragments are now delivered before the session ends.

---

## v0.1.0

**Date:** 2026-10-20
**Previous release:** none

## Summary

The first version: a DNP3 (IEEE 1815-2012) master and outstation in pure
Go, with the link layer, the transport function, the application layer and
its object library, file transfer and Secure Authentication v5 with
pre-shared keys. Verified as master and as outstation against Step
Function I/O dnp3 1.7.0, opendnp3 3.1.2 and DSC Systems go-dnp3 v0.8.1, and
as outstation against dnp3py 0.6.0, with the images of dnp3-interop v0.1.0.

## Changes

### Added

- **Link layer** (`link`, `internal/channel`) — FT3 frames and CRCs, a stream reader that resynchronises after damage, unconfirmed and confirmed user data with reset of link states and the frame count bit, test link states, link status keep-alive, broadcast and self addresses, several associations per channel.
- **Transport function** (`transport`) — segmentation and reassembly by the rules of clause 8.
- **Application layer** (`app`) — fragments, IIN, qualifiers, and an object library for every group in use: binary, double-bit, binary output, counters, frozen counters, analog inputs, frozen analog inputs, deadbands, analog outputs and their events and commands, time objects, class objects, file control (g70), internal indications, device attributes (g0), BCD and small integers, octet strings, virtual terminal objects and the secure authentication objects (g120..g122). Data set and private registration objects are carried raw.
- **Client** (`client`) — the master: reads and polls, controls (select-before-operate, direct operate, no-ack, set-points), time synchronization by both procedures, restarts, unsolicited control, assign class, freezes, device attributes, file transfer; unsolicited responses with confirmation; automatic handling of the internal indications; periodic polls; reconnect, retries, queue limit; TCP, TLS, UDP and any byte stream.
- **Server** (`server`) — the outstation: a point database with classes, variations, deadbands and batches; event buffers per master that survive reconnects; multi-fragment responses with confirmation; unsolicited responses with hold time and retries; select-before-operate with timeout and sequence checks; pattern control; freezes; restarts; time synchronization; assign class; device attributes; file transfer with a read-only `fs.FS` file server; any number of masters and connections; TCP, TLS, UDP and any byte stream.
- **Secure Authentication v5** (`secauth`, `WithSecureAuthentication`) — challenge of critical requests and HMAC replies with a pre-shared session key; session key status.
- **Observability** — `Logger`, `FieldLogger`, `ContextLogger` and `log/slog` adapters; `Metrics`, `RequestMetrics`, `ServerMetrics`; state notifications.
- **Tests** — known vectors, round trips of every variation, fuzz targets for every decoder, link procedure tests frame by frame, chaos tests on noisy and duplicating lines, an outstation conformance suite with a scripted master, end-to-end tests of every function, stress tests with many masters and concurrent requests, and the interop suite.
- **Examples** — `quickstart`, `commands`, `events`, `files`, `secure`, `observability`, and a standalone `server` and `client`.
