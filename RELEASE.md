# go-dnp3 Releases

## v0.2.1

**Date:** 2026-10-20
**Previous release:** v0.2.0

## Summary

Secure Authentication fixes found by the interop tests against DSC
Systems go-dnp3, the first other stack with SAv5 in dnp3-interop. The
interop suite now covers dnp3-interop v0.2.0 (contract 1.1): TLS, UDP,
serial, file transfer and Secure Authentication, in both directions. No
API change.

## Changes

### Fixed

- **The master replied to a challenge with a new sequence number.** The authentication reply (g120v2) now keeps the sequence number of the challenge, which is that of the critical request, and the response to the request is expected with it (IEEE 1815-2012 clause 7.4). An outstation that follows this, as DSC Systems go-dnp3 does, ignored the reply's answer and the request timed out. The outstation accepts either.
- **Every key change after the first failed against DSC Systems' outstation.** The master put the key status message into the key change data with its MAC value. The first key status after a connection has none, so only a second key change within one connection (`client.WithKeyChangeInterval`) was refused. The master now leaves the MAC out, the form every known outstation accepts; go-dnp3's outstation still accepts both.
- **DSC Systems' master could not answer go-dnp3's challenges.** The outstation sent 16 octets of challenge data; it now sends 32, which that master requires and the standard allows.

### Tests

- Interop tests for dnp3-interop contract 1.1, both directions: TLS with mutual authentication against a generated test PKI, UDP (against opendnp3's outstation from a container on its network), serial over a bridged pseudo-terminal, file transfer against the files fixture, and Secure Authentication with session key changes and a wrong update key.

---

## v0.2.0

**Date:** 2026-10-20
**Previous release:** v0.1.1

## Summary

The Secure Authentication session key change, and a fix for the UDP
outstation. Both found by the interop work for dnp3-interop's contract 1.1.

**Upgrade notes**

- `secauth.User` has a new `UpdateKey`. With it the session keys are negotiated; without it the pre-shared `Key` is used as before, so existing configurations keep working.

## Changes

### Added

- **Session key change** (IEEE 1815-2012 clause 7.5.2.3) in both roles. The master requests the key status (g120v4), wraps fresh control and monitoring direction session keys with the update key (AES-128 or AES-256 key wrap, RFC 3394) together with the key status message (g120v6), and checks the outstation's confirmation (g120v5 with a MAC over the key change, computed with the new monitoring key). It does so on every connection and at `client.WithKeyChangeInterval` (default 15 minutes). The outstation drops the session keys when the connection ends. The key status message is sent with its MAC value; the outstation accepts it with or without, as implementations differ.
- `secauth.KeyWrap`, `KeyUnwrap`, `KeyChangeData`, `ParseKeyChangeData`, `User.UpdateKey`, `User.KeyWrapAlgorithm`, `User.SessionKeyLen`.
- `app.AppendObjectValue`, the encoding of one object without its header.
- `server.ServeUDPTo`: DNP3 over UDP with the master's address known from the start, so that unsolicited responses reach it before it sends.

### Fixed

- **The UDP outstation stopped before any master spoke.** With one configured master, the association exists at once and sends its null unsolicited response. With no peer known yet, that write failed and ended `ServeUDP`, so every later request was lost. A datagram with nowhere to go is now dropped, as UDP would, and the unsolicited retries repeat it.

---

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
