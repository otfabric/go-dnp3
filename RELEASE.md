# go-dnp3 Releases

## v1.2.0

**Date:** 2026-10-20
**Previous release:** v1.1.0

## Summary

Several outstations behind one port or line (multi-drop), as IEEE 1815
addresses them and opendnp3, stepfunc dnp3 and DSC go-dnp3 serve them; and
`client.Measurements` reports every kind of point data. No breaking change.

## Changes

### Added

- **`server.Group`** (`NewGroup(servers...)`): several outstations, each a `Server` with its own link address, database, handler and options, on the same connections, serial lines or UDP sockets: `ListenAndServe`, `Serve`, `ServeConn`, `ServeUDP`, `Close`. A frame goes to the outstation it is addressed to, a broadcast to all of them, also as a master's first frame. The connection limit is the smallest `WithMaxConnections` of the servers.

### Fixed

- **`Measurements` left out the time and interval (g50v4), BCD integers (g101) and unsigned integers (g102).** They are point data like any other: an application had to walk `Result.Headers` to see them, as dnp3ctl did. The other variations of group 50 (the time of time synchronization and freezes) are still not measurements.

### Tests

- Interop: the masters of stepfunc, opendnp3, DSC go-dnp3 and dnp3py reach each of three go-dnp3 outstations behind one port by its link address; an address nobody has is not answered.
- One connection with sessions to several outstations, broadcasts to all of them, the limits and the lifecycle of a group.

---

## v1.1.0

**Date:** 2026-10-20
**Previous release:** v1.0.0

## Summary

What dnp3-interop's contract 1.3 tests, in both roles. No breaking change.

## Changes

### Added

- `Client.Broadcast(ctx, dest, fc, headers...)`: a request to the broadcast addresses 0xFFFD, 0xFFFE or 0xFFFF; the outstations answer nothing and set IIN1.0 in their next response.
- `client.FileOptions.Append`: `WriteFile` appends to the file (OPEN_FILE in APPEND mode).
- The outstation answers READ of g34, the deadbands of its analog inputs.
- **Device attribute sets** other than set 0: `server.WithAttributeSet(set, attrs, writable...)` with `AttributeSetWriteHandler`, and `Client.ReadAttributeSet`, `WriteAttributeSet`. A writable attribute takes a value of its type and the outstation keeps it.
- **Scheduled FREEZE_AT_TIME** (IEEE 1815-2012 A.23.2): a time to come is waited for and an interval repeats the freeze until `Close`, up to `server.MaxScheduledFreezes` waiting; time 0 freezes at once. A time that has passed, without an interval, is refused.

### Changed

- FREEZE_AT_TIME with a time to come or an interval is carried out, where it was refused with PARAMETER_ERROR; one with a time that has passed and no interval is now refused, where it froze at once.

### Tests

- Interop against dnp3-interop v0.4.1 (contract 1.3), both directions where a reference has the feature: device attributes, several controls in one request, freeze at time and analog freeze, deadbands, file append and authentication, event buffer overflow, link confirms and keep-alive, broadcast, the management functions, several outstations behind one port.

### Fixed

- **The values of `link.BroadcastConfirm` and `link.BroadcastOptionalConfirm` were swapped.** IEEE 1815 has 0xFFFE for a broadcast whose confirmation is mandatory and 0xFFFF for one where it is optional, as opendnp3 and DSC go-dnp3 do; go-dnp3 had them the other way round. `BroadcastNoConfirm` (0xFFFD) was right. go-dnp3 treats the three alike, so only code that compared against the values sees a difference.
- **With secure authentication, a critical broadcast was carried out unauthenticated.** A broadcast cannot be challenged, so the outstation executed a critical request sent to a broadcast address (a control, a freeze, a write) without any MAC; v1.0.0 has this too. Such a request is now carried out only in aggressive mode with a valid MAC; otherwise it is discarded, counted as a discarded message and not answered.
- **An outstation ignored a broadcast that was the master's first frame**: it had no association for the master yet. It now accepts the master on a broadcast frame as on any other.

---

## v1.0.0

**Date:** 2026-10-20
**Previous release:** v0.2.1

## Summary

The first production release. It completes Secure Authentication with
aggressive mode and security statistics, adds the dual end point (an
outstation that connects to its master), and fixes what a new full-stack
chaos test, parallel tests and an outstation fuzz target found. The
interop suite covers every feature the dnp3-interop v0.2.0 images offer,
in both directions. From this release on the API follows semantic
versioning: no breaking change without a new major version.

**Upgrade notes**

- `client.Connect` now closes the channel when the startup sequence fails (for example a refused session key change), so the client is disconnected afterwards. It used to report the error but keep the channel open. `client.Dial` is unchanged: it already closed the client.
- `client.New` refuses `WithAggressiveMode` without `WithSecureAuthentication` (`ErrInvalidOption`).
- `server.PointType` has new values after `OctetString`: `SecurityStatistic`, `BinaryOutputCommand`, `AnalogOutputCommand` and `TimeAndInterval`. A `switch` over point types may need cases for them. `Database.Add` refuses the first three, which the outstation keeps itself; `TimeAndInterval` points are added like the others, without a class.

## Changes

### Added

- **Aggressive mode** (IEEE 1815-2012 clause 7.5.2.2.4), both roles. `client.WithAggressiveMode` sends critical requests with a g120v3 object first and a g120v9 MAC over the last challenge and the request last, so the outstation executes them without a challenge. The outstation verifies the MAC and the challenge sequence number. Verified between go-dnp3's own ends: no reference in dnp3-interop implements it.
- **Security statistics** (clause 7.6): the outstation keeps the 18 statistics per association (`secauth.Statistic`), serves them as g121v1 and reports g122v2 events every `SecureAuth.StatisticsThreshold` increments in `SecureAuth.StatisticsClass`. Verified against DSC Systems go-dnp3 in both directions.
- **Dual end point** (annex A.3): `server.DialAndServe` connects to the master, serves the connection and reconnects with backoff (`server.Redial`), with TLS as the TLS client; `client.Accept` makes the master wait for the outstation's connection.
- **Time and interval** (g50v4): `server.TimeAndInterval` points (`app.AbsoluteTime` with `Units`), read by group and variation; like the reference outstations, not in class 0.
- **Command events** (g13, g43): an output whose `PointConfig.CommandEventClass` is set reports every executed OPERATE, DIRECT OPERATE and DIRECT OPERATE NO ACK as an event with the commanded state or value and the handler's status (`CommandEventVariation`, default g13v2 and g43v3).
- `server.SecureAuth.ReplyTimeout` (default `DefaultReplyTimeout`, 10 s): a challenge reply that arrives later is refused.
- `secauth.DefaultCritical` (shared by both roles; `server.DefaultCritical` is the same slice) and `secauth.AggressiveOverhead`.

### Fixed

- **A master without session keys stayed without them until the next key change interval** (15 minutes by default) when a key change at connect failed while the connection stayed up, or when the outstation refused its keys. It now changes them again right after an authentication failure, and keeps retrying with a backoff from 1 second while it has none.
- **`Client.Close` waited for a reconnection attempt to time out** (up to 10 seconds, or longer for a slow dial). It now ends the attempt at once.
- **File writes failed with aggressive mode, or with a receive fragment smaller than the transmit one.** The outstation sized written blocks for its responses only; it now also fits them in a request of its receive size, with room for the aggressive mode objects when secure authentication is on. The master leaves that room too.

### Tests

- A full-stack chaos test: a proxy that corrupts octets, splits and delays writes, and kills connections, while polls, controls, file reads, database updates and, with secure authentication, session key changes run at once. It checks that no data that was not sent is accepted, that no control is executed more often than it was sent, that everything recovers when the faults stop, and that nothing keeps running after Close.
- Parallel masters with their own session keys, aggressive mode, controls and file transfers against one outstation.
- `FuzzOutstation`: arbitrary request fragments into an outstation with secure authentication, file transfer and every point type (`make fuzz`, in CI).
- Interop against dnp3-interop v0.3.0 (contract 1.2): the dual end point in both roles over TCP and TLS; the extended fixture (frozen analog inputs, command events, time and interval) in both directions; security statistic events in both directions; the dnp3py fixture against all four outstations, dnp3py's included.
- Interop: requests without a response in both directions (DIRECT OPERATE NO ACK, FREEZE AND CLEAR NO ACK), reads of all objects of a group by the reference masters, security statistics in both directions. INTEROPERABILITY.md has the coverage matrix and the comparison with the reference stacks.
- In-package tests of file transfer on both ends, the dual end point and the new procedures.

### Docs

- Package documentation for `client` and `server`; doc comments on every exported field of the authentication, file and error types.
- Every document reviewed against the code: the new APIs in API.md, Secure Authentication in ARCHITECTURE.md and SECURITY.md, the new log entries in OBSERVABILITY.md, the dual end point and `Connect`'s behaviour in ERRORS.md, the interop coverage matrix and the remaining gaps in INTEROPERABILITY.md, and a `dialout` example.

---

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
