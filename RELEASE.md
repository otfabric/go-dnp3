# go-dnp3 Releases

## v1.12.1

**Date:** 2026-11-12
**Previous release:** v1.12.0

## Summary

A change of test evidence only: `make interop` and `make conformance` move from otfabric/dnp3-interop v0.11.2 to v0.12.0 (contract 1.5, unchanged). The library is the same as v1.12.0: no code outside the interop suite changes, no exported API, no protocol behaviour.

## Changes

### Testing

- **dnp3-interop v0.12.0**: the five reference images are pinned by their v0.12.0 digests in `interop/harness.go`, the Makefile and the Interop workflow, and `make conformance-image` builds the dnp3c runner from the v0.12.0 commit (`31ce30d5`). Of the references only cB-Sigma dnp3 changes, from v0.3.0 to v0.3.1; opendnp3 3.1.2, DSC go-dnp3 v0.8.2, dnp3py 0.6.0 and nfm-dnp3 1.0.1 are unchanged.
- **GET_FILE_INFO names in the interop suite** (IEEE 1815-2012 4.4.18, p. 75: the answer carries the file name of the request): `TestClientFiles` now checks the name of the descriptor go-dnp3's master receives, and `TestServerFiles` the name each reference master reports from go-dnp3's outstation. The outstations of DSC go-dnp3 v0.8.2 and cB-Sigma dnp3 v0.3.1 answer with the last path element; the suite logs that as a known bug of each (`file-info-base-name`, the rows `dscsystems-file-info-base-name` and `cbsigma-file-info-base-name` of dnp3-interop's `tests/known-bugs.tsv`) instead of failing.
- **`TestServerDualEndPoint` over TLS** retries the race it already retried, with Docker's port proxy accepting a dial that go-dnp3's outstation has already dropped, also when the listening master reports it as a failed TLS handshake (`connect-failed`), as cB-Sigma dnp3's master of the v0.12.0 image does now and then (EOF, or a first record that is not a handshake); up to three attempts, as before, so a TLS fault of its own still fails the test. Locally the subtest failed 2 of 16 runs before and passed 20 of 20 after (one retry).

### Documentation

- README.md, INTEROPERABILITY.md, SECURITY.md and docs/FEATURE-STATUS.md name dnp3-interop v0.12.0 and cB-Sigma dnp3 v0.3.1; INTEROPERABILITY.md records the GET_FILE_INFO names of the two outstations as known bugs; the status line of docs/FEATURE-STATUS.md names go-dnp3 v1.12.0.

---

## v1.12.0

**Date:** 2026-11-12
**Previous release:** v1.11.0

## Summary

Caller-supplied dialers on every path that dials (otfabric engineering policy 1.5, rule API-R03), so that an application can apply an address allowlist against the resolved IP, dial through a proxy or a jump host, bind a source address, or test over an in-memory connection. The outstation's dial-out (`DialAndServe`) takes a dialer and a reconnect jitter; the client's UDP gets a dialer-taking variant; both ends hold dialers to the contract of `net.Dialer`. Exported API is added, none removed or changed. No protocol behaviour changes. It also fixes the build for 32-bit platforms (linux/arm, linux/386), which v1.11.0 broke.

## Upgrading

- **The `error` of the `DialAndServe` reconnect log record** (`connection to the master lost, reconnecting`) now wraps `dnp3.ErrConnectFailed` after a failed dial or TLS handshake; the TLS handshake failure is prefixed `TLS handshake:`, as on the client. Its `delay` is the delay before the next attempt, with `Redial.Jitter` applied (equal to before without jitter).
- A dialer of `client.WithDialer` that returns neither a connection nor an error now fails `Connect` with `dnp3.ErrConnectFailed`; it made `Connect` panic before; a connection returned together with an error is closed.

## Changes

### Fixed

- The `client` package compiles again on 32-bit platforms (linux/arm, linux/386; v1.11.0 does not): the error message of `WithKeyChangeCount` passed `MaxKeyChangeCount` (`1 << 31`, an untyped constant) as an `int`. `make cross` now covers linux/386 and type-checks the tests on every platform, `make check` runs it, and CI has a Cross-compile job.

### Master

- `client.UDPWithDialer(d, addr)`: the `StreamOpener` of `UDP` with the connected UDP socket opened by a caller's dialer (network `"udp"`); `UDP` and `UDPFrom` are built on it and behave as before. `WithStream` openers do not use `WithDialer`; the doc comments of `WithDialer`, `UDP` and `UDPFrom` and LIMITATIONS.md say so.
- Dialer contract on `Connect`, the reconnects and the dual end point's own dial, which all dial through `WithDialer`: a dialer that returns neither a connection nor an error fails the dial; a connection returned together with an error is closed; the dialer's error is wrapped in `dnp3.ErrConnectFailed`, so `errors.Is` reaches its own sentinels. The doc comment of `client.Dialer` states the contract and the context a dialer must honour.

### Outstation

- `server.WithDialer(Dialer)` and the `server.Dialer` interface (the shape of `client.Dialer`; `*net.Dialer` satisfies it): the dialer of `DialAndServe`. It is called with network `"tcp"`, the master's address and a context that carries the 10 s dial timeout and ends with `DialAndServe`'s context or `Close`; with `WithTLS` the handshake runs over its connection (`tls.Client`). nil keeps the default, a `net.Dialer` with a 10 s timeout, unchanged. The same contract as the client's.
- `Redial.Jitter` (0 to 1) draws each reconnect delay d of the doubling backoff from [(1-Jitter)·d, d], with the semantics of `client.Reconnect.Jitter`, so that outstations that lost their connections together do not reconnect together. Zero, the default, keeps the exact doubling; a value outside 0 to 1 makes `DialAndServe` return `dnp3.ErrInvalidOption` before it dials.

### Added API

- `client`: `UDPWithDialer(Dialer, addr)`.
- `server`: `Dialer`, `WithDialer(Dialer)`, `Redial.Jitter`.

### Testing

- Dialer tests on both ends: the network, address and deadline the dialer receives, the caller's cancel, error wrapping with `errors.Is`, the nil-connection case, a connection returned with an error being closed, TLS over the dialer's connection, and transport faults injected through the dialer (a `net.Pipe` end closed mid-session, then the reconnect or redial through the same dialer) for the client and for `DialAndServe`.
- `Redial.Jitter`: validation, the bounds of each drawn delay, and the measured gaps between redials.

### Documentation

- SECURITY.md: an address allowlist belongs in the dialer (`net.Dialer.Control` sees the resolved IP right before connecting); checking the host name before dialling leaves a DNS-rebinding gap. SECURITY.md supports 1.12.x.
- API.md, ERRORS.md, OBSERVABILITY.md, LIMITATIONS.md, INTEROPERABILITY.md and `docs/api` updated for the dialers and the jitter.
- Policy: otfabric engineering policy 1.5 (`.otfabric/policy.yaml`, `policy-version` v1.5.0 in the workflows, AGENTS.md).

---

## v1.11.0

**Date:** 2026-11-11
**Previous release:** v1.10.0

## Summary

A review of the whole library against IEEE 1815-2012, clause by clause, with the fixes it called for and a spec test for each requirement checked: 305 test functions named after their clause (`TestSpec<clause>_…`, see [TESTING.md](TESTING.md#spec-tests)), in the unit tests of every package and in `e2e`. Several defaults and behaviours change where the standard requires it; read **Upgrading** first. Exported API is added, none removed. This is not a certification: the evidence is in INTEROPERABILITY.md.

## Upgrading

- **The master runs an integrity poll at connect, and answers NEED_TIME by itself** (5.1.1.2, 4.5.5). `WithStartup(client.Startup{})` and `WithTimeSync(client.TimeSyncNone)` restore the old behaviour, for example for one-shot tools.
- **An outstation rejects a second connection of a master that is connected** when the first connection answers a link status request (13.2.3.3); a broken first connection is still replaced. Two clients with the same link addresses can no longer share one outstation.
- **Aggressive mode MAC follows Table A-9**: it does not interoperate with go-dnp3 releases before this one. Upgrade both ends.
- **Secure Authentication timing**: the outstation's reply timeout is 2 s (was 10 s), session keys expire after 30 minutes or 2000 messages without a change, and more function codes are challenged by default.
- **TLS uses port 19999 by default** (7.8.8): `ListenAndServe("")` with `WithTLS`, and a client with `WithTLS` given an address without a port. Plain TCP stays on 20000.
- **SAVE_CONFIG is answered with a Delay Time object** (g52v2, 4.4.12): a master that expects a response without objects, such as opendnp3's, reports a bad response.
- **Security statistics carry Association ID 0** (A.46.1.2.2: measured on the association that reads them), not the master's address.
- **Frozen counter and frozen analog input events are raised at every freeze**, also for an unchanged value (11.9.5.2, 11.9.1.2): a master that polls events sees one per freeze and point.
- **Responses with qualifier 0x06, group 60 or variation 0 are refused** by the codec: these headers are for requests only.
- **A master with an update key does not send a critical request without valid session keys**: a function Table 7-7 marks MANDATORY, or one `WithAggressiveMode` names, fails at once with `dnp3.ErrAuthentication`, unsent, and the session keys are changed. Before, it was sent, and failed on the challenge.

## Changes

### Master

- **Startup and restart procedures.** `Connect` runs an integrity poll by default (`Startup{Integrity: true}`, 5.1.1.2). `EnableUnsolicited` classes also disable unsolicited reporting and poll first (5.1.1.2 Rule 1). When an outstation reports a restart (IIN1.7), the client runs the procedure of 5.1.1.1.2 in order: session key change (with secure authentication), clear of IIN1.7, time synchronization, integrity poll, ENABLE_UNSOLICITED for the `Startup.EnableUnsolicited` classes. At connect, IIN1.7 is cleared once, right after DISABLE_UNSOLICITED.
- **NEED_TIME is answered** (4.5.5): the LAN procedure over TCP, TLS and UDP, the non-LAN one over other streams, and non-LAN from then on when an outstation refuses LAN. `TimeSyncClearNeedTime` clears the indication instead of setting the clock; `TimeSyncNone` does nothing. Time synchronization requests always go as UNCONFIRMED_USER_DATA (10.3.4.1). The LAN procedure writes the time at which RECORD_CURRENT_TIME left; the non-LAN one measures the round trip to the arrival of the response, before it is decoded. `DelayMeasure` reports the round trip of the attempt that was answered.
- **Select before operate**: OPERATE follows only an echo equal to the request octet for octet (4.4.4.3 Rule 8); another echo fails with `dnp3.ErrProtocol`. A control response that stops at the first failed object (4.4.4.3 Rule 6) reports that object's status as a `*dnp3.CommandError`. A `Command` with the Queue bit, or with a status other than 0 or 126, fails with `dnp3.ErrInvalidOption` before anything is sent (A.8.1.2.2).
- **Multi-fragment responses** (Table 6-2): a repeat of the last fragment is confirmed again; any other unexpected fragment abandons the response with `dnp3.ErrProtocol`.
- **Opt-in jitter for retries and reconnects.** `Retry.Jitter` and `Reconnect.Jitter` (0 to 1) draw each pause d of the doubling backoff from [(1-Jitter)·d, d], so that masters that lost their connections together do not retry or reconnect together. Zero, the default, keeps the exact doubling; a value outside 0 to 1 fails the option with `dnp3.ErrInvalidOption`. The `retry_in` of the `reconnect failed` warning is now the delay before the next attempt; it named the previous delay.
- **Unsolicited responses**: a repeat is one with the sequence number and the octets after the IIN of the previous one. A repeat that reports a restart is processed; one with the same sequence number and new content is processed and followed by an integrity poll (4.6.6 Rule 7). A response whose UNS bit contradicts its function code is ignored and not confirmed. The confirmation goes out before the next request (4.3 Rule 13).
- Values of the variations without flags (g1v1, g3v1, g10v1, g20v5–8, g21v9–12, g30v3–4, g31v5–6) read as ONLINE (11.6.5); they read as zero flags before.
- `WriteFile` sets the file's time of creation (`FileOptions.Created`, default now), sends no more than the size it was given, and sizes blocks to `WithMaxRequestFragment`.
- With `WithTLS`, an address without a port uses port 19999 (`client.DefaultTLSPort`, 7.8.8).
- One `WithSecureAuthentication` option used for several clients no longer races: each client gets its own copy of the user.
- **A failed `Connect` no longer leaves a reconnect running.** With `WithReconnect`, a `Connect` whose connection broke during its startup sequence returned the error while the client went on reconnecting in the background; the next `Connect` then dialled next to that reconnect, and the channel one of them opened replaced the other's without closing it. The orphan went on answering link status requests, so an outstation that keeps the connection of a connected master (13.2.3.3) refused every later connection. A failed `Connect` now leaves the client disconnected, as documented, and a channel is never replaced while another is open.
- **No automatic task on the channel of a failed `Connect`.** A task queued during the startup sequence (the restart procedure after IIN1.7, a time synchronization) could send one request on the channel that `Connect` was about to close after the startup failed. Queued tasks now see the client disconnected and are dropped.
- **No goroutine after `Close`.** A `Close` during `Connect` could return before a goroutine of the client started: the channel's watch, the reconnect loop after a startup sequence whose connection was lost, or the dual end point's accept. That goroutine then ran after `Close` (the race detector reported the `sync.WaitGroup` misuse). Each is now registered under the lock where `Close` marks the client closed.

### Outstation

- **Frozen events at every freeze**: a frozen counter or frozen analog input with an event class raises an event at every freeze, also when the value did not change (11.9.5.2, 11.9.1.2).
- **Requests**: a request with CON set is confirmed (4.3 Rule 12); a fragment with UNS set or without FIR and FIN is discarded (4.2.2.4.4, 4.3 Rule 4); a request repeated while the confirmation of its response is awaited gets that response again (Table 6-1 row 17); a CONFIRM sent to a broadcast address is ignored. A READ received while the confirmation of an unsolicited response is awaited is answered after it (4.6.6 Rule 16).
- **Unsolicited**: DISABLE_UNSOLICITED ends a pending series without retries; the null unsolicited response is retried until confirmed; a retry is identical to the first, and a regenerated response takes the next sequence number.
- **IIN**: IIN1.0 cleared per Table 4-13; a master may clear IIN1.4 with WRITE g80v1 index 4; IIN1.4 belongs to the device clock, not to one master; IIN2.3 stays set until every event buffer has room; an `ApplicationHandler` may return IIN2.4.
- **Controls**: a request status of NON_PARTICIPATING (126) is echoed (Table 11-7 note a); a CROB with the queue bit is answered NOT_SUPPORTED (A.8.1.2.2); a request with an unknown header executes nothing; a request between SELECT and OPERATE, or a failed SELECT, ends the selection; a SELECT with the same sequence number and other octets is discarded; the echo of a control request is held to the transmit limit.
- **Files**: an open file no request names for `WithFileTimeout` (default 5 minutes) is closed and reported with a g70v6 HANDLE_EXPIRED event (4.4.17.1.1, 5.3.8 Rule 12); handles are unique to the outstation; a block beyond the declared size or larger than negotiated is BUFFER_OVERRUN; an unknown mode INVALID_MODE; deleting an open file FILE_LOCKED; a failed abort CANNOT_ABORT; CLOSE_FILE and ABORT_FILE echo the request; GET_FILE_INFO answers with the requested name; `FSFileServer` reports permissions as read only and a directory's size as its number of entries (Table 11-8).
- **FREEZE_AT_TIME** follows Table 4-11: time 0 with an interval freezes every interval from the start of the current hour; the time all ones cancels. FREEZE_CLEAR of analog inputs is answered IIN2.1 (Table 12-14).
- **Application functions**: SAVE_CONFIG through `ApplicationHandler` is answered with g52v2 (delay 0), as 4.4.12 requires; opendnp3's master refuses a response with objects to it and reports a bad response, although the function was executed. ACTIVATE_CONFIG is answered with g91v1. INITIALIZE_DATA is obsolete (4.4.10): without a handler it is answered IIN2.0.
- **ASSIGN_CLASS** accepts g12v0 and g41v0 (command events); security statistics to class 0 are answered IIN2.0; `Server.Restart` reverts class assignments.
- **Reads**: g50v1 with qualifier 0x07, count 1, returns the time (other qualifiers IIN2.2); packed variations can be read by index; an octet string asked in another length is answered in its own length; g0v255 uses qualifier 0x17; an index or count qualifier on group 0 selects the set; a READ of group 0 without attribute sets is IIN2.1; a virtual range qualifier (0x03–0x05) in a request is answered with the same qualifier.
- **Point data**: ROLLOVER and reserved flag bits are cleared; a +Inf deadband is accepted and suppresses events; output events are not raised for points left out of class 0; the g13 commanded state of PULSE_ON is 1. `WithDeadbandIntegerOnly` reports analog input deadbands in g34v1 and v2 only (A.18.3.2.3).
- DELAY_MEASURE above 65535 ms is answered with 65535 ms instead of no answer. WRITE with no values (and WRITE g80v1 with qualifier 0x06) is IIN2.2.
- **No connection served after `Close`.** A connection that `Server.Serve` or `Group.Serve` accepted as `Close` closed the listener was handed to a goroutine that could start while `Close` waited for the server's goroutines, or after it returned (the race detector reported it). Such a connection is now closed, and `Serve` returns nil.

### Link layer, transport function and DNP3 over IP

- **Connections of a connected master** (13.2.3.3): a new TCP connection from a master that is already connected is rejected when the existing connection answers a link status request; a dead (half-open) one is replaced as before. A bare TCP connect no longer closes the master's connection when one master is configured. Requests that arrive on the new connection while the outstation probes the old one are held, and answered if the new connection is taken.
- An outstation closes a TCP connection on which no master has sent a frame within one keep-alive interval plus the link timeout (62 s by default; 13.2.3.3.1).
- **UDP**: every datagram is read whole and every frame in it decoded (13.2.3.2.3); a damaged datagram no longer affects the next one. The UDP socket of an outstation is no longer closed when a keep-alive goes unanswered, and a UDP datagram from a master no longer evicts the same master's TCP connection, so broadcasts over UDP reach a TCP-connected outstation. `ServeUDPFixed` answers a fixed master address (Table 13-1 case 1); `client.UDPFrom` sends from a fixed local address, for an outstation that answers a fixed port of the master.
- **Master IP validation**: `server.WithMasterIPs` accepts masters by IP address (13.2.3.2.2 d, 13.2.3.1.4 a); `server.ServeByMasterIP` routes connections to outstations by master IP (13.2.3.5.1, method 1).
- **Dual end point**: `client.WithDualEndpoint` makes the master a TCP dual end point: it dials the outstation and also takes the connections the outstation establishes, one at a time, the master having priority (13.2.3.1.3); an `allow` function validates the outstation's address (13.2.3.1.4 b); `DialAndServe` no longer dials the master while a connection from it is up.
- The DIR bit of received frames is ignored (9.2.4.1.3.1). Frames to the self address 0xFFFC are taken only by an outstation with `WithSelfAddress`, also in a `Group`; the master ignores them (9.2.5.2.2).
- A link status request answered with anything but LINK_STATUS no longer closes the connection; the answer is logged and counted as an error (Table 9-6). An unanswered one leaves the link unreset (Table 9-6 rows 20 and 34).
- With `Link.Confirmed`: a repeated CONFIRMED_USER_DATA is acknowledged and discarded; one that would overflow the receive queue is answered NACK with DFC set; a NACK with DFC set is not repeated (9.2.7.2, Table 9-6 row 28); TEST_LINK_STATES with an unexpected FCB repeats the last ACK or NACK (9.2.6.2). A channel over TCP or UDP with `Link.Confirmed` logs a warning: 13.2.1.1 forbids confirmed link frames over IP.
- A transport segment that repeats the previous one is discarded without losing the fragment being assembled (8.2.1.4, Table 8-1); an empty segment is rejected (`transport.ErrDuplicate`, `transport.ErrNoData`).
- `ListenAndServe` with `WithTLS` and an empty address listens on port 19999 (`server.DefaultTLSPort`, 7.8.8).

### Secure Authentication

- **Aggressive mode** MAC covers every octet of the request up to the MAC value, the g120v9 object header and its size prefix included (Table A-9). **Wire change**: upgrade both ends. The master falls back to a challenged request when the outstation refuses one.
- **Critical functions**: the function codes Table 7-7 marks MANDATORY are always challenged (`secauth.MandatoryCritical`); a `SecureAuth.Critical` list without them is completed with them. `DefaultCritical` (secauth and server) adds ENABLE_UNSOLICITED, DISABLE_UNSOLICITED, RECORD_CURRENT_TIME, CLOSE_FILE, GET_FILE_INFO and ABORT_FILE; this set is also the default of `client.WithAggressiveMode`.
- **Outstation, challenger state machine** (Table 7-8): a challenge carries user number 0 (A.45.1.2.2). `DefaultReplyTimeout` is 2 s (7.6.1.4.1), and the reply timer runs: an expired challenge is discarded and counted, and past Max Reply Timeouts the session keys become invalid (COMM_FAIL). While a challenge waits for its reply, other requests are discarded and counted. A reply nobody asked for, or an invalid aggressive mode request while a challenge waits, is discarded without an error message. Aggressive mode is accepted only after a valid reply since the last session key change.
- **Outstation, limits**: error messages (g120v7) stop past Max Error Messages Sent until the next valid session key change. Past Max Authentication Failures the session keys become invalid (AUTH_FAIL); when this happens again past Max Authentication Rekeys, a TCP connection is closed (Table 7-8 row 11).
- **Outstation, keys**: session keys expire after `ExpectedKeyChangeInterval` (30 min) or `ExpectedKeyChangeCount` (2000 authentication messages) without a change (7.6.1.4.5); the pre-shared session key mode is exempt. After a reconnect the key status is COMM_FAIL, with a MAC by the last monitoring key (Table 7-8 row 9). An invalid session key change makes the keys invalid (AUTH_FAIL) and moves the KSQ. A key status request for an unknown user is answered with g120v5 AUTH_FAIL (A.45.5). Past `MaxKeyStatusRequests` key status requests within the expected key change interval the outstation logs an error, and still answers them (7.6.1.4.6).
- **Outstation, statistics**: Association ID 0, meaning this association (A.46.1.2.2). Each statistic has its own event threshold, with the defaults of Table 7-6 instead of 10 for all; a `StatisticsThreshold` that is set still applies to all. Statistics count CONFIRMs and repeated fragments; Authentication Failures is reported at each session key change. `Server.Restart` zeroes the challenge and key change sequence numbers.
- **Master, key changes**: after `WithKeyChangeCount` authentication messages (default 1000, 7.6.1.4.4) as well as at the interval (`WithKeyChangeInterval(0)` turns the interval off); when the outstation reports a restart, up to 3 times in a row (7.5.4.2); after an authentication error, up to 3 times until a key change succeeds, and past that, over TCP, the connection is closed (Table 7-8 row 11). Key change retries back off at most 3 times, then wait for the interval.
- **Master, aggressive mode** is used only after a challenge was answered since the last session key change. After a refused aggressive mode request the next one is challenged; an outstation that answers error 4 is not sent aggressive mode again on that connection. A critical request that fits `WithMaxRequestFragment` only without the aggressive mode objects goes without them and is challenged (7.4.1.6: the master may anticipate the challenge, it need not); it takes no challenge sequence number, so the next aggressive mode request is accepted (`TestSpec7_4_1_6_AggressiveOverRequestLimit`).
- **Master, no-ack requests** (DIRECT_OPERATE_NR, …) sent without aggressive mode wait up to the response timeout for the outstation's challenge and answer it; before, they reported success while the outstation discarded the request. Without a challenge they still return nil, after the wait; a g120v7 fails them with `*dnp3.AuthError`.
- **Master, no critical request without session keys**: with an update key and no valid session keys, a critical request (Table 7-7 MANDATORY, or a `WithAggressiveMode` function) fails with `dnp3.ErrAuthentication` without being sent, and asks for a session key change. Sent, it could only fail, as the master discards the challenge (Table 7-13 row 7), and the outstation, waiting for the reply, discards the key status request (Table 7-8 row 16): a master that repeated such requests at once never got its keys back. `TestChaos` found this; `TestSpecTable7_13_CriticalNotSentWithoutKeys` covers it.
- **Master, other**: CONFIRMs to a response that ends with a challenge are sent in aggressive mode, and a challenge of a CONFIRM is answered. The session key status is authenticated: an OK status needs a MAC by the last monitoring key, its user and its key wrap algorithm must match, and a key change confirmation whose status is not OK fails the change. 8-octet MACs are refused by default over TCP and UDP (7.6.1.1); `WithChallengeMACs` can allow them.

### Codec (`app`)

- **Negative BCD values**: `app.BCD` has a `Negative` field. A g101 value whose most significant BCD character is 0xA..0xF decodes as negative (11.3.6.1); it was rejected as malformed, and the fragment with it. A negative value is sent with the sign character 0xF; a value with more digits than the variation holds is refused with `ErrInvalidValue`.
- **Responses with qualifier 0x06, class objects or variation 0 are refused** (Table 4-8, 4.2.2.7.1.1, 4.2.2.7.2.1): `Encode` of a response with one fails with `ErrInvalidQualifier` or `ErrInvalidValue`; `Decode` reports one with `ErrInvalidQualifier` or `ErrMalformed` and returns the headers before it. Requests are unchanged.
- **Index qualifiers above 65535**: `IndexQualifier`, and so `IndexList`, `Indexed` and the outstation's responses, use 0x37 or 0x38 rather than 0x39 when an index needs four octets and the count fits one or two, and 0x29 for more than 65535 objects with 2-octet indexes (4.2.2.7.3.4). Nothing changes while every index and the count fit two octets.
- **Floating-point attributes** are 4 or 8 octets: another size is refused by `Encode` (`ErrInvalidValue`) and reported malformed by `Decode` (11.4, 5.5.4.3).
- **CROB and analog output status widths**: the CROB (g12v1) status is 7 bits; bit 7 is reserved, sent as 0 and no longer read. The analog output block (g41) status is the full octet, 0..255; it was cut to 7 bits (A.8.1.2.2, A.20.1.2.2).
- **g81v1 and g82v1 decode**: the device storage buffer fill status (g81v1) into `app.BufferFillStatus` (`app.G81V1`), the device profile (g82v1, `app.G82V1`) as `app.Raw`. A response that held either failed to decode as a whole. Group 100 is still not supported: IEEE 1815-2012 defines no coding for it.
- Clause and table citations in the `app` godoc corrected.

### Added API

- `client`: `Retry.Jitter`, `Reconnect.Jitter`, `WithMaxRequestFragment(n)` (at least 249, 4.3 Rule 4; a request that does not fit fails with `dnp3.ErrInvalidOption`), `Client.ClearNeedTime(ctx)`, `TimeSyncClearNeedTime`, `DefaultTLSPort`, `FileOptions.Created`, `WithDualEndpoint(l, allow)`, `UDPFrom(local, remote)`, `WithKeyChangeCount`, `DefaultKeyChangeCount`, `MaxKeyChangeCount`, `Client.SecurityStatistics`.
- `server`: `WithMasterIPs(prefixes...)`, `Route` and `ServeByMasterIP(l, routes...)`, `Server.ServeUDPFixed(pc, peer)`, `DefaultTLSPort`, `WithFileTimeout(timeout, class)` and `DefaultFileTimeout`, `WithDeadbandIntegerOnly(enabled)`; `SecureAuth` gains `Thresholds`, `NoAggressiveMode`, `ExpectedKeyChangeInterval`, `ExpectedKeyChangeCount` and `MaxKeyStatusRequests`, with `DefaultExpectedKeyChangeInterval`, `DefaultExpectedKeyChangeCount` and `DefaultMaxKeyStatusRequests`.
- `secauth`: `MandatoryCritical`, `Statistic.DefaultThreshold`.
- `app`: `BCD.Negative`, `BufferFillStatus`, `G81V1`, `G82V1`.
- `transport`: `ErrDuplicate`, `ErrNoData`.

### Testing

- 305 spec test functions named after the clause they check, in `spec_*_test.go` files of `app`, `link`, `transport`, `internal/channel`, `secauth`, `client`, `server` and `e2e`.
- `TestSubsetLevelTables` (outstation) and `TestSubsetLevelResponses` (master) walk the request and response rows of Tables 14-2 to 14-4 at subset levels 1 to 3.
- `make interop`: the suite expects Association ID 0 in the security statistics and opendnp3's refusal of the SAVE_CONFIG delay object; the in-network UDP master (`interop/testdata/udpmaster`) opts out of the startup sequence, since it retries its poll itself.
- `TestChaos` keeps the last 3000 lines the master and the outstation logged and prints them when a run fails, with the attempts each recovery check needed.
- Four defects found by the link spec tests are fixed: an unanswered REQUEST_LINK_STATUS left the link reset; TEST_LINK_STATES with an unexpected FCB always answered ACK; `WithSelfAddress(true)` never answered 0xFFFC; `ServeUDPFixed` accepted a TCP peer.
- `TestFrameChaos` drops, duplicates and reorders whole link frames between a master and an outstation with a fixed seed, and checks that every failure is a documented error, that no control runs more often than it was sent and that the session recovers. `DNP3_CHAOS_SEED` replays the seed a chaos run logged.
- Fuzz targets `FuzzDecodeFileDescriptors` and `FuzzParseActivateConfigStatus` (`app`), in `make fuzz`; hand-written seed corpora for them and for `FuzzReassembler`, `FuzzPack` and `FuzzKeyUnwrap`.
- `internal/leaktest` checks that goroutines and, on Linux and macOS, open file descriptors return to their number before the test; the `Close` lifecycle tests of `client` and the stress tests of `e2e` use it.
- CI: golangci-lint v2.15.0 in CI as locally (the reusable workflow defaulted to v2.1.6); otfabric/.github reusable workflows v3.6.0; a CodeQL workflow (Go) on pushes and pull requests to `main` and weekly.

### Documentation

- INTEROPERABILITY.md: clause references in every layer table; DNP3 over IP (clause 13): end points, keep-alive, address validation, multiple masters; the Secure Authentication device profile items; subset levels; frozen counter events; deviations and choices (unsolicited at startup, INITIALIZE_DATA, repeated READ, DELAY_MEASURE, open with block size 0, class 0 and g110, reads of absent types).
- LIMITATIONS.md, API.md, ERRORS.md and SECURITY.md updated for the changes above; TESTING.md describes the spec tests.
- API.md lists `link.Function.HasData`, `UsesFCB` and `link.Address.Reserved`; SECURITY.md supports 1.11.x; OBSERVABILITY.md and ERRORS.md describe the retry and reconnect jitter; TESTING.md the chaos seed, the frame-level chaos test and the leak check.

---

## v1.10.0

**Date:** 2026-11-11
**Previous release:** v1.9.1

## Summary

Fixes from a review against two vendor DNP3 documents (an Emerson flow computer manual and a RACOM link layer description). Exported API is added, none removed.

## Changes

### Master

- **The reply to a challenge uses the MAC algorithm the challenge names.** The master refused a challenge whose MAC algorithm differed from the one in its `secauth.User`, so an outstation that challenges with, say, HMAC-SHA-1/10 refused every control of a master left on the default HMAC-SHA-256/16, and each refusal started a session key change. It now replies with the challenge's algorithm, and aggressive mode requests use the algorithm of the challenge their MAC covers. `WithChallengeMACs(algs...)` limits the algorithms accepted; by default every algorithm `secauth` computes is accepted except the obsolete HMAC-SHA-1 truncated to 4 octets.

### Master and outstation

- **Secure authentication user number 0 is taken as 1.** IEEE 1815-2012 reserves user number 0 for an unknown user; a `secauth.User` left without a `Number` sent 0, which an outstation refuses. `client.WithSecureAuthentication` and `server.WithSecureAuthentication` now take 0 as 1, the default user. `secauth.User.Validate` is unchanged.

### Testing

- A capture of unknown origin joins the corpus (`testdata/captures/unknown-origin/`, class C): integrity polls, unsolicited g2v2 events and 134 SELECT and 133 OPERATE requests of a master that sends the next request before the previous answer. The capture harness now pairs such pipelined requests with their responses by sequence number, and pairs the RESPONSE after a secure authentication challenge with the challenged request. The manifest records a source of unknown origin as such.

### Documentation

- LIMITATIONS.md: the session key lifetime (a time, not a message count; the outstation does not expire keys), frames for another address (unsolicited responses sent to a destination other than the master's), and file reads (answered at once, one block per READ).
- INTEROPERABILITY.md: link function codes the standard does not define are ignored, as the certification procedure 6.6.2.2 accepts; the security statistics that stay 0.

---

## v1.9.1

**Date:** 2026-11-08
**Previous release:** v1.9.0

## Summary

Validation against recorded DNP3 traffic of other software: 182 captures (the ITI ICS-Security-Tools DNP3 captures, among them 140 runs of a conformance runner against the opendnp3 3.0 outstation with the runner's logs, the Zeek DNP3 traces and the igbe attack data set), committed byte-identical with their sources, revisions and SHA256. Every frame is decoded, encoded back octet for octet and checked against Wireshark's dissector and the runner's own decoding; the master and the outstation are replayed against the recorded peers. One outstation defect found this way is fixed. The recordings are software-generated or of unknown origin (evidence classes C and D): nothing here is a statement about DNP3 hardware. No exported API is added or removed.

## Changes

### Outstation

- **READ of g0v0 answers IIN2.1.** Group 0 has no variation 0; an outstation without device attribute sets answered it with IIN2.2 (PARAMETER_ERROR), one with sets with IIN2.1. It now answers IIN2.1 (OBJECT_UNKNOWN) alone in both cases, as procedure 8.6.3.2 of the DNP3 IED certification procedure verifies and the recorded opendnp3 outstation answers (`conformance-runner_opendnp3-3_8-6-3-2.pcap`, frame 4).

### Testing

- `testdata/captures`: the corpus, `manifest.json` (source, revision, original name and URL, SHA256, size, evidence class, peers, operations, limitations, files examined and not committed), `SHA256SUMS`, `coverage.json` (what the codecs find per file), Wireshark's decoding of every file (`tshark/`) and the conformance runner's logs. `make captures-verify` checks the SHA256 (CI job `Captures`); `make captures-oracle`, `captures-report` and `captures-seeds` regenerate the derived files.
- `internal/capture` (test infrastructure): pcap and pcapng reader (Ethernet, BSD loopback, IPv4, TCP reassembled per direction with retransmissions, gaps and reused address pairs, UDP), and the corpus tests: 13690 link frames and 12456 fragments encode back to the recorded octets; link, transport and application headers, IIN and object headers agree with Wireshark in every frame but the classified ones; the runner's logged octets are the reassembled streams, and its decoding of 1063 link, 1024 transport and 968 application rows, 1206 object headers and 4858 values agrees with go-dnp3's; every framing and decode error (45) is classified.
- `client`: 5543 recorded requests replayed through `Request` and `Broadcast`, byte-identical apart from the sequence number, with the recorded responses (5534 fragments, 82142 measurements) and 647 unsolicited responses accepted and confirmed; `ReadFile`, `ListDirectory`, `WriteFile`, `DeleteFile`, select before operate, LAN and non-LAN time synchronization, `DelayMeasure` and restarts against the recorded outstations.
- `server`: 5569 recorded requests sent to the outstation and its answers compared with the recorded ones (answered or not, sequence, IIN2 errors, control echoes), every difference classified; the link-layer octets of the link procedures (resets, link status, confirmed data, invalid FCV, damaged frames) replayed with the same link reactions as the recorded outstation.
- 370 fuzz seeds from the captures for `FuzzDecode` and `FuzzReader` (`link`), `FuzzDecode` (`app`), `FuzzOutstation` (`server`) and `FuzzMaster` (`client`).

---

## v1.9.0

**Date:** 2026-11-04
**Previous release:** v1.8.0

## Summary

Hardening from a low/low static analysis scan (gosec, opengrep): every narrowing integer conversion is range-checked where the scanner can see it, and the defects it pointed at are fixed. File transfer with fragments over 65547 octets failed on every block; it now works at both ends. A few out-of-range inputs that were sent wrapped are refused. New fuzz targets for the master and for session key change data, and an end-to-end test of file transfer over large fragments. No exported API is added or removed.

## Changes

### Outstation

- **File block size fits its object.** The block size announced at OPEN_FILE was the fragment size less 20, sent in two octets: with fragments over 65555 octets and a master that left the size to the outstation it was announced modulo 2^16 (100000-octet fragments announced 34444) while larger blocks were sent, and any block over 65527 octets could not be encoded, so every READ of the file was answered without its block. Blocks are now at most 65527 octets, the most a g70v5 object holds beside the handle and block number.
- **Files of 4 GiB or more.** `FSFileServer` opened them with their size modulo 2^32; it now refuses them with FILE_FATAL, and directory listings and GET_FILE_INFO give them the size 0xFFFFFFFF.
- A WRITE of an attribute of a set over 65535 no longer looks up the set modulo 2^16 before it is refused with PARAMETER_ERROR (the answer was already right).

### Master

- **`FreezeAtTime` checks its interval.** A negative interval, or one of 2^32 ms (about 49.7 days) or more, was sent modulo 2^32; it is now an `ErrInvalidOption` and nothing is sent.
- **`WriteFile` blocks fit their object.** An outstation announcing a block size over 65527 got a WRITE that could not be encoded; blocks are now at most 65527 octets.

### Objects

- `OctetStringGV(g, n)` returns variation 0 for a length outside 1..255 instead of the length modulo 256 (257 gave variation 1, -1 gave 255). No value encodes under variation 0, so such a string is refused when it is encoded.

### Testing

- `FuzzMaster` (`client`): the master, with Secure Authentication configured, against an outstation that answers every request with the fuzz input as a response, a continuation or an authentication response. Requests must end within their timeouts and Close must return.
- `FuzzKeyUnwrap` (`secauth`): AES key unwrap and the parsing of session key change data.
- `e2e/largefragment_test.go`: read and write of a 300000-octet file over 100000-octet fragments.
- Regression tests for each fix above, and for the two's complement helpers of the object codecs.

### Tooling

- The interop fixture compares the file password in constant time; the catalog generator and the upstream watch write their files with mode 0600 and clean the paths they read.
- go-ci and the release workflow use otfabric/.github v3.3.1.

---

## v1.8.0

**Date:** 2026-11-03
**Previous release:** v1.7.0

## Summary

Go 1.26 is now the minimum Go version. The exported API and the wire behaviour are unchanged.

### Changed

- `go.mod` requires Go 1.26 (was 1.23). CI tests Go 1.26 and 1.27.
- The code base has been modernised with `go fix ./...`: `sync.WaitGroup.Go`, `errors.AsType`, `slices.Backward`, `slices.Contains`, `strings.SplitSeq`, `min`, and range-over-int loops. There is no change in behaviour.

---

## v1.7.0

**Date:** 2026-11-03
**Previous release:** v1.6.0

## Summary

Hardening of event reads and of the event lifecycle against IEEE 1815-2012,
checked behaviour by behaviour with wire-level tests at both ends. Two
outstation fixes: a READ of events with a count of zero returned every
event, and a point given an event class by ASSIGN_CLASS measured its next
change from the value it was added with. The master accepts an
AUTHENTICATE_FILE answer with empty strings at offset 0. The interop suite
runs against dnp3-interop v0.11.0, with two more reference stacks: cB-Sigma
dnp3 v0.3.0 (both roles) and nfm-dnp3 1.0.1 (master). No API change.

## Changes

### Outstation

- **An event header with a count of zero names no event.** A READ of g60v2..v4 or an event group with qualifier 0x07, 0x08 or 0x09 and a count of 0 returned all buffered events, as if it had no count; it now returns none and leaves them buffered and indicated (IIN1.1..1.3). Counts above zero were already honoured, the oldest events first (IEEE 1815-2012 clause 4.2.2.7.3).
- **A point without an event class follows its value.** Updates of a point in class 0 produce no event, but the outstation kept comparing later updates with the value the point had when it was added. Once ASSIGN_CLASS gave the point a class, a change back to that value raised no event, and the master kept the value it had read in class 0. The next event is now measured from the point's current value; deadbands apply from it.

### Master

- **g70v2 with empty strings decodes at any offset.** cB-Sigma dnp3 v0.3.0 answers AUTHENTICATE_FILE with an empty user name and password whose offsets are 0; the decoder required offset 12 and dropped the answer, so `AuthenticateFile` timed out. Empty strings point at nothing, so their offsets are no longer checked; non-empty strings must still start at offset 12, and the encoder still writes 12.

### Interop

- **dnp3-interop v0.11.0**: images pinned by digest in `interop/harness.go`, the Makefile and the Interop workflow, with `DNP3_INTEROP_CBSIGMA_IMAGE` and `DNP3_INTEROP_NFMDNP3_IMAGE` to override them.
- **cB-Sigma dnp3 v0.3.0** passes every test of the features it declares, as master and as outstation: TCP, TLS, UDP, serial, dual end point, file transfer with append and authentication, Secure Authentication v5, contract 1.3.
- **Dual end point**: the poll is retried, at most twice, when the listening master reports the connection lost before it polled. Docker's port proxy accepts the outstation's redials before the master in the container listens and can hand the master one already dropped.
- **nfm-dnp3 1.0.1**, a master over TCP, is served the baseline without unsolicited responses (it cannot confirm them). Integrity polls, all-objects reads, controls and event polls are skipped with the known bug of each, reported upstream (fxodell/dnp3py#5, #7, #10).

### Tests

- `app`: an AUTHENTICATE_FILE answer with empty strings at offset 0 (cB-Sigma dnp3's) decodes and re-encodes at offset 12; a non-empty string at another offset is still malformed; a `FuzzDecode` seed.
- Scripted-master tests with exact requests (`server/eventread_test.go`): limited event reads with one- and two-octet counts, confirmed and unconfirmed, and with a count of 0 in one-, two- and four-octet counts; a READ of one event group in a buffer of several groups and classes; g2v1, g2v2 and g2v3 (CTO) reads and configured event variations; per-point event class and ASSIGN_CLASS; class 0 exclusion for every static type; CON on responses with events and not on those without; a confirmation removes the events of its response only, not those buffered since; unsolicited events kept and repeated until confirmed; FREEZE_AT_TIME_NR, IMMED_FREEZE_NR and FREEZE_CLEAR_NR executed and never answered, also when they fail or do not decode; COLD_RESTART and WARM_RESTART answered with g52v2 or g52v1, IIN2.1 without a `RestartHandler`.
- Master against scripted outstations (`client/confirm_test.go`): a solicited or unsolicited fragment that asks for confirmation is confirmed only when it parsed whole; a truncated object, or one the codec cannot size, leaves it unconfirmed and its events undelivered; one without CON is never confirmed.
- End-to-end (`e2e/eventread_test.go`): draining events four at a time delivers each once and in order; an event group read across classes; ASSIGN_CLASS of points added without a class; analog output status out of class 0 with its g42 events; offline points reported with their flags; FREEZE_AT_TIME_NR without waiting for a response.

### Documentation

- README, INTEROPERABILITY.md (coverage matrix with cB-Sigma dnp3 and nfm-dnp3, their findings), FEATURE-STATUS, TESTING and SECURITY name dnp3-interop v0.11.0 and the two stacks.
- INTEROPERABILITY.md describes count-limited and per-group event reads and when the master confirms; LIMITATIONS.md lists event headers with range or index qualifiers, the absence of a periodic freeze of the outstation's own, and that output status follows the application.

---

## v1.6.0

**Date:** 2026-11-02
**Previous release:** v1.5.4

## Summary

ACTIVATE_CONFIG with its answer, the status of requested operation (g91v1),
at both ends, and two client options to withhold application confirmations
for tests. The codec decodes g91v1 with a count qualifier, as DSC go-dnp3
sends it, where it took only free format: a master dropped such an answer
and timed out. Public API additions only.

## Changes

### Codec

- **g91v1 with a count or range qualifier**: the object delimits itself (time delay, count, then length, status code and text per entry; IEEE 1815-2012 Annex A, group 91), so `app.Decode` now takes it with a count (0x07, 0x08), range or free-format qualifier. `Decode` of DSC go-dnp3's answer `C0 81 00 00 5B 01 07 01 00 00 00 00 01 01 00` failed with `app: invalid qualifier: 0x07 for free-format g91v1`. A g91v1 object is still an `app.Raw`, and a free-format one is still carried as it is, whatever its content; one sent without a size must be a valid status (`app.ErrInvalidValue` otherwise).
- **`app.ActivateConfigStatus`** (`Delay`, `Results`) and **`app.ActivateConfigResult`** (`Code`, `Text`): `app.ParseActivateConfigStatus(data)` reads the data of a g91v1 object (`app.ErrMalformed`), `ActivateConfigStatus.Raw()` encodes one (`app.ErrInvalidValue`).

### Outstation

- **`server.ActivateConfigHandler`**, an optional interface of the `Handler`: `ActivateConfig(ctx, headers) (app.ActivateConfigStatus, app.IIN)`. When the handler implements it, ACTIVATE_CONFIG goes to it instead of `ApplicationHandler`, and the response carries the status in one g91v1 object with qualifier 0x07; an IIN2 error bit answers without it. A status that does not encode or fit a fragment is answered with PARAMETER_ERROR. `ApplicationHandler` is unchanged and still answers ACTIVATE_CONFIG with IIN bits only when the handler has no `ActivateConfig`.

### Master

- **`Client.ActivateConfig(ctx, headers...)`** sends ACTIVATE_CONFIG with file specifications (g70v8) or octet strings (g110) and returns the status of every g91v1 object of the response; `dnp3.ErrProtocol` when there is none or it does not parse. It is never retried.
- **`client.WithSolicitedConfirm(bool)`** and **`client.WithUnsolicitedConfirm(bool)`**, on by default: off, the client confirms no solicited, or no unsolicited, response. They are test and diagnostic options, to watch an outstation keep unconfirmed events or repeat an unconfirmed unsolicited response; a multi-fragment response stalls after its first fragment without confirmations.

### Tests

- Known vectors, error paths and round trips of g91v1 in count, range and free-format qualifiers, with DSC go-dnp3's answer; the vectors are seeds of `FuzzDecode` and its corpus in `app/testdata/fuzz/FuzzDecode`.
- A scripted master with the exact ACTIVATE_CONFIG request and its g91v1 answer (`server/conformance_test.go`), a client against scripted outstations, and e2e tests of ACTIVATE_CONFIG and of both confirmation options (`e2e/activateconfig_test.go`).

---

## v1.5.4

**Date:** 2026-11-02
**Previous release:** v1.5.3

### Changed

- Removed interop test functionality against this stack, as requested by the maintainer of this stack: the Step Function I/O dnp3 (stepfunc) reference image. `make interop`, the Interop workflow and `interop/harness.go` no longer build or run it, and the upstream watch (`.github/upstream.json`, `internal/cmd/upstreamwatch`) no longer follows its object definitions.
- Interop runs against opendnp3, DSC go-dnp3 and dnp3py from [dnp3-interop v0.9.0](https://github.com/otfabric/dnp3-interop/releases/tag/v0.9.0), pinned by digest; the conformance run's dnp3c runner from the same release.
- README, INTEROPERABILITY, ARCHITECTURE, CONTRIBUTING, TESTING and docs/FEATURE-STATUS list the stacks go-dnp3 is tested against. No change in the library.

---

## v1.5.3

**Date:** 2026-11-01
**Previous release:** v1.5.2

### Fixed

- **Data race when a client turns a request away with `ErrBusy`.** The error read the queue length after the lock was released, while another request could leave the queue. Found by the race detector in `TestChaos`, once.
- **A client no longer runs two reconnects at once.** A reconnect whose session key change failed while the channel was lost took that for a failed dial and went on dialling, next to the reconnect of the lost channel. An outstation serves one connection per master, so each dial closed the other's and the reconnects fed each other, also after the faults had stopped: requests failed with `ErrBusy`, and a response could reach the request of another channel. Seen with secure authentication.
- **An outstation holds back a READ that follows an unsolicited response.** The time of sending was taken after the send returned, so a READ from a fast master could count as sent first, and was answered while the response waited for its confirmation.

### Tests

- Regression tests: a full queue under the race detector, and one reconnect when the key change fails on a lost channel.

---

## v1.5.2

**Date:** 2026-11-01
**Previous release:** v1.5.1

### Changed

- Interop runs against dnp3-interop v0.8.0 (contract 1.4), pinned by digest. No change in the library.
- Regression tests of the outstation's frozen counter events (`EventOnChange`, unchanged): a freeze of an unchanged counter sets the snapshot and its time and raises no event; value and flag changes raise theirs; event classes, time stamps in g23v5, g23v6 and g21v5, confirmation and replay. `interop/counters_test.go` runs them against reference masters, and a go-dnp3 master against outstations whose counters really change.
- `INTEROPERABILITY.md`: this is go-dnp3's policy. What IEEE 1815 says of it has not been read, and nothing here claims the standard permits or prohibits it.

---

## v1.5.1

**Date:** 2026-10-31
**Previous release:** v1.5.0

### Changed

- Policy 1.2: build output in `bin/` and `release/`, a per-package coverage floor, and more tests and CI. No change in behaviour.

---

## v1.5.0

**Date:** 2026-10-30
**Previous release:** v1.4.1

## Summary

Hardening of both ends against hostile or unlucky peers: bounded READ and
ASSIGN_CLASS work, TLS handshake timeouts, listeners and UDP sockets that
survive transient errors, and panics contained to one request. The
outstation keeps the quality and time quality of more values. The master
synchronizes the time before its startup integrity poll and no longer
fails the startup sequence on a step the outstation rejects. Interop runs
against dnp3-interop v0.6.0 (with DSC go-dnp3 v0.8.2).

## Changes

### Outstation

- **Bounded READ work**: a READ plans at most four complete reads of the database (plus 1024 objects); headers beyond that, such as hundreds of repeated class 0 headers, are answered with IIN2.2 instead of holding the database for seconds.
- **Bounded ASSIGN_CLASS work**: a range header walks the points that exist, not every index it names, so `0..0xFFFFFFFF` takes as long as the database is large instead of minutes under the database lock.
- **Deadbands**: `Add` refuses a NaN, infinite or negative `PointConfig.Deadband` (`ErrInvalidOption`), and a WRITE of one (g34) is answered with IIN2.2. A NaN deadband silently stopped events for value changes, and a negative one raised an event for every update.
- **Frozen analog inputs without flag** (g31v5, g31v6) whose flags are not ONLINE alone are reported with flags (g31v1, g31v2), like the other analog inputs. An ONLINE analog input whose value an integer variation without flag cannot carry (out of its range, NaN) is reported with flags too, which say OVER_RANGE, instead of as a clamped number.
- **Events recorded while the time was unsynchronized**: binary and double-bit input events in the default or configured variation (g2v2, g4v2) are reported with relative time (g2v3, g4v3) under an unsynchronized CTO (g51v2), even when they are read after a time sync; a master that asks for g2v2 or g4v2 still gets them. The CTO of relative-time events now reflects when each event was recorded, not when it was read.
- **TLS handshake timeout**: an accepted TLS connection must finish its handshake within 10 s, or it is closed (`TLS handshake failed`); a peer that stalls it no longer holds a connection slot. `DialAndServe` bounds its dial and handshake the same way.
- **Accept errors**: `Serve` (and `Group.Serve`) keep accepting after an `Accept` error other than a closed listener, such as running out of file descriptors, with a pause that doubles up to a second; before, any error but a timeout stopped the listener for good.
- **UDP**: `ServeUDP` keeps serving after a read or write error that concerns one datagram (an ICMP unreachable, a send to a route that went away); only a closed socket ends it.
- **Panics**: a panic while serving a request, in go-dnp3 or in the application's `Handler`, is logged with its stack and the request goes unanswered; the association and the process go on.

### Master

- **Time sync before the integrity poll**: when the outstation asks for the time (NEED_TIME) and `WithTimeSync` is set, the startup sequence synchronizes it before its integrity poll, and the automatic tasks after a restart queue the time sync before the integrity poll, so the poll's events carry synchronized time.
- **Startup steps the outstation rejects**: a step answered with an error IIN (an `IINError`, such as IIN2.0 to DISABLE_UNSOLICITED from an outstation without unsolicited responses) is logged (`startup step rejected`) and the sequence goes on; before, `Connect` failed and closed a working channel.
- **Timeouts**: the default dialer has a 10 s connect timeout, and the TLS handshake is bounded to 10 s, so `Connect(context.Background())` against an outstation that stalls it fails instead of hanging.
- **UDP**: a client on `UDP(addr)` keeps its socket after an ICMP port unreachable (an outstation not listening yet, or restarting), which a connected UDP socket reports as ECONNREFUSED; the request is repeated by the response timeout instead of the channel being lost.
- **Panics**: a panic while receiving a fragment, in go-dnp3 or in the application's handler, is logged with its stack and the fragment is lost; the client and the process go on.

### Security

- **Secrets in formatted output**: `app.FileAuthentication` and `secauth.User` format and log (`String`, `GoString`, `LogValue`) without their password, authentication key or keys, so printing a decoded request or a configuration does not reveal them.

### Tests

- Interop against [otfabric/dnp3-interop v0.6.0](https://github.com/otfabric/dnp3-interop/releases/tag/v0.6.0): DSC go-dnp3 v0.8.2, and go-dnp3's master and outstation are also tested against more ASSIGN_CLASS and DIRECT_OPERATE_NO_ACK peers.
- `TestDeferredReadTakesUnsolicitedEvents` gives the READ a second before the unsolicited confirm timeout, so a slow runner under the race detector no longer fails it.

---

## v1.4.1

**Date:** 2026-10-21
**Previous release:** v1.4.0

## Summary

The last open point of the IED certification run is closed: a control
whose request carries a status is no longer carried out (TB2014-002), so
3.1r1 passes without a warning. A go-dnp3 master reports a control the
outstation answers NOT_SUPPORTED, with IIN2.2, with its statuses again.
Interop runs against dnp3-interop v0.5.1.

## Changes

### Outstation

- **Controls with a request status** (TB2014-002; IEEE 1815-202x; 3.1r1 8.2.6): a SELECT, OPERATE or DIRECT_OPERATE whose control block carries a nonzero status is answered with FORMAT_ERROR without calling the `Handler`, instead of being carried out. A Handler's `Command.Value` now always has status zero.

### Master

- **NOT_SUPPORTED controls**: a control response that sets an error IIN but echoes the request reports its statuses, as a `CommandError` with the status of the first control that failed, instead of an `IINError`. Since v1.4.0, a go-dnp3 outstation sets IIN2.2 with NOT_SUPPORTED, as opendnp3 always has; against all of them `Operate` returns the statuses again. A response without an echo is still an `IINError`.

### Tests

- Interop against [otfabric/dnp3-interop v0.5.1](https://github.com/otfabric/dnp3-interop/releases/tag/v0.5.1): its published images pinned by digest, the locally built image from its source; the conformance run's dnp3c runner from the same release.

---

## v1.4.0

**Date:** 2026-10-21
**Previous release:** v1.3.2

## Summary

A security fix: a malformed READ of a file transport object could crash the
outstation process. Upgrade if a master you do not control can reach your
outstation.

Every deviation that the DNP Users Group's IED certification procedures
found in the outstation is fixed. The procedures (dnp3c: 3.1 rev 1 at subset levels 2 and 3, 2.7 at level 2) now pass and run
in CI.

Some answers change, and a go-dnp3 master reports them differently:

- a control answered NOT_SUPPORTED, and a read of a point type the
  outstation has none of, now come back as an `IINError`;
- an OPERATE after the select timeout now gets TIMEOUT;
- a READ sent while an unsolicited response awaits its confirmation is now
  answered only after it.

## Changes

### Security

- **A crash on a malformed request** (security): a READ of g70v5 (file transport) under a qualifier that carries indices but no objects made the outstation panic and took the whole process down, for any master that can reach it (v1.3.2 and earlier). The outstation now answers it, and every other header whose objects lack the value their variation needs (controls, time writes, the IIN bits, deadbands, octet strings, attributes, freeze at time), with IIN2.2. The master no longer assumes the time delay object of a restart or delay measurement response either. Found by `FuzzOutstation` in CI; the input is kept as a seed.

### Outstation

- **Controls** (3.1r1 8.2.1.2.3, 8.2.1.2.4, 8.2.1.2.10, 8.4.1.2.x): an OPERATE that matches its SELECT but comes after the select timeout is answered with TIMEOUT, not NO_SELECT (IEEE 1815-2012 Table 11-4). A control the handler answers with NOT_SUPPORTED, for example of a point the outstation does not have, also sets IIN2.2 (PARAMETER_ERROR), as opendnp3 does; the echo is still sent. A go-dnp3 master reports such a response as an `IINError` instead of a `CommandError`.
- **CTO of relative-time events** (3.1r1 8.14.2m, 8.15.3, 8.22m): with `WithTimeSync`, g51v2 (unsynchronized) until the first time synchronization after the start or a restart, and again once twice the interval has passed without one; g51v1 otherwise, also while IIN1.4 asks for the next synchronization. It was always g51v1. A restart (`Server.Restart`, or a COLD_RESTART or WARM_RESTART handler that calls it) now forgets the synchronization: IIN1.4 and g51v2 until the next one.
- **Reads of variations without flags** (3.1r1 8.24.2d to 8.24.2f): a counter, frozen counter or analog input whose flags are anything but ONLINE alone is reported with flags (g20v1/v2, g21v1/v2, g30v1/v2) when g20v5/v6, g21v9/v10 or g30v3/v4 is read, as the packed binary variations already were, so that its quality is not hidden.
- **Reads of a type without points** (3.1r1 8.13.2d, 8.16.1.2.4, 8.21, 8.22, 8.24.2b): a read of the static or event objects of a type of input or output point the outstation has none of is a null response with IIN2.1 (OBJECT_UNKNOWN), as TB2016-001 and the 3.1r1 procedure require; it was a null response without it. A read of the events of a type the outstation has, while it has no events of it, is still a plain null response. A go-dnp3 master reports the response as an `IINError`.
- **Broadcast indication** (3.1r1 8.6.5b): after a broadcast to 0xFFFE (confirmation required) or 0xFFFF (optional), the response that reports IIN1.0 asks for an application confirmation, and IIN1.0 is cleared when it arrives; it never asked for one. After a broadcast to 0xFFFD, IIN1.0 is still cleared once reported.
- **READ while an unsolicited response waits for its confirmation** (3.1r1 8.11.2a, 8.11.2.5): the READ is answered once the response is confirmed, or once its confirm timeout expires and before it is repeated (IEEE 1815-2012 4.6.6 rule 16, TB2015-002a), instead of at once. A READ from another master than the one the response went to, or one that came before it (the datagram that starts a UDP session), is answered at once; a later request supersedes the deferred READ, which is then not answered. A repeated unsolicited response carries the indications as they are when it is repeated, e.g. without IIN1.7 once the master cleared it, instead of those of its first transmission. A READ answered at the confirm timeout reports the events of the unconfirmed unsolicited response, which is then not repeated (8.11.2.5), and no unsolicited response is repeated while a solicited one is in progress, between its fragments or before its confirmation. `Unsolicited.Retries` below zero repeats an unsolicited response until it is confirmed (3.1r1 8.11.2.5 configures it).

### Tests

- **IED conformance procedures in CI** (`make conformance`, [conformance.yml](.github/workflows/conformance.yml)): dnp3c 0.2.0 runs the DNP3 IED Certification Procedure, 3.1 rev 1 at subset levels 2 and 3 and 2.7 at level 2, against a test outstation built on the library ([internal/cmd/conformance](internal/cmd/conformance)), with its Device Profile in `device.ini` there. dnp3c runs in [otfabric/dnp3-interop](https://github.com/otfabric/dnp3-interop)'s dnp3c runner image, which `make conformance-image` builds from dnp3-interop's source at `CONFORMANCE_COMMIT`; dnp3c and the runner are GPL-3.0-only, are not in this repository, and the image is not published. Not a certification.
- **Fuzzing failures can be reproduced**: the CI fuzz job uploads the inputs a failing target writes (this is how the crash above was found).

---

## v1.3.2

**Date:** 2026-10-21
**Previous release:** v1.3.1

## Summary

Interop against dnp3-interop v0.4.3, whose four adapters now follow its
container contract and one of whose images is built locally, and an
interop test that no longer fails when a master's first requests cross
opendnp3's startup unsolicited response. No change of the library.

## Changes

### Tests

- Interop against [otfabric/dnp3-interop v0.4.3](https://github.com/otfabric/dnp3-interop/releases/tag/v0.4.3): its published images pinned by digest (`interop/harness.go`, Makefile, `.github/workflows/interop.yml`), and the remaining image built locally from dnp3-interop's source at the release's commit. Its upstream's licence allows testing with the library but not redistributing it, so that image is no longer published ([dnp3-interop#19](https://github.com/otfabric/dnp3-interop/issues/19)); `make interop` and the interop workflow build it first.
- The no-ack and broadcast interop tests wait 15 s for the effect: opendnp3 can leave a READ unanswered until its unsolicited confirm timeout (5 s) when it sent its next unsolicited response before the confirm of the first arrived. go-dnp3 confirmed both in order; the test failed about one run in forty. Recorded in [INTEROPERABILITY.md](INTEROPERABILITY.md#interop-coverage).

---

## v1.3.1

**Date:** 2026-10-20
**Previous release:** v1.3.0

## Summary

The documentation reviewed for correctness before the repository goes
public: every claim checked against the code, the comparison with the
other DNP3 stacks checked against their sources. No change of
behaviour.

## Changes

### Docs

- **The comparison with the other stacks** (README) corrected from their sources: DSC go-dnp3 has `log/slog`, `context.Context` and blocking requests, `Stats()` counters, data sets and the IED conformance procedures (dnp3c) in CI; opendnp3 and DSC can both run an outstation that dials its master; rows for multi-drop, data sets and the conformance procedures added. The Limitations name the conformance procedures go-dnp3 does not run.
- **Error semantics** (ERRORS.md, `dnp3.ErrProtocol`): a response with an unexpected sequence number is ignored, not an `ErrProtocol`; a request whose headers do not encode returns the codec error; which methods return a `*Result` together with an `*IINError`; what the `Serve` methods return after `Close`; what is retried.
- **Observability** (OBSERVABILITY.md, `dnp3.FieldLogger`): which loggers receive debug entries; the fields of each entry and the entries that were missing; the state handler on failed reconnects and on `Close`.
- **API.md**: the exported names that were missing, and the values a `Measurement` carries.
- **INTEROPERABILITY.md**: the multi-drop row, which did not render; the qualifiers, function codes and default variations as implemented; pre-shared session keys listed as a deviation; the interop matrix and the data set capabilities of DSC go-dnp3 corrected.
- **OBJECTS.md**: what Point and Kind mean, and variation 0 of the open-ended groups.
- **ARCHITECTURE, CONTRIBUTING, SECURITY**: the segment size, the state the transport keeps, the tests that exist, the release notes convention, the supported versions, aggressive mode on the outstation.
- **Citations**: the dual end point and g86v2 cite IEEE 1815-2012 without the annex subclauses, which were wrong.
- **examples/observability** shows the outstation's metrics too, as its description says.

---

## v1.3.0

**Date:** 2026-10-20
**Previous release:** v1.2.0

## Summary

The objects come from one catalog that generates the codec's table, the
points `client.Measurements` reports and OBJECTS.md; a weekly upstream
watch compares it with the upstream stacks and looks for a new
dnp3-interop release. g86v2 is now decoded as the one octet IEEE 1815-2012
defines.

**Upgrade notes**

- g86v2 (Data Set Descriptor - Characteristics) now decodes to `app.DataSetCharacteristics`, not `app.Raw`. It is a correction to IEEE 1815-2012 Annex A, released as a fix: code that type-asserted `app.Raw` for g86v2 must switch to the new type.

## Changes

### Added

- **An upstream watch**: a weekly workflow that opens or updates an issue when the object definitions of an upstream stack change, when the sizes they define differ from the catalog, or when dnp3-interop has a new release (`make upstream-watch` runs it locally).
- **OBJECTS.md**: every group and variation with its kind, size and whether it is point data.
- **`app.DataSetCharacteristics`** and **`app.DataSetFlags`**: the g86v2 object and its RD, WR, ST, EV and DF bits.

### Changed

- **The objects come from one catalog.** `app/catalog.json` lists every group and variation; the codec's table, the variations `client.Measurements` reports and OBJECTS.md are generated from it (`make generate`), and CI fails when they drift. The table is the same as before for every other object.

### Fixed

- **g86v2 (Data Set Descriptor - Characteristics) is one octet, as IEEE 1815-2012 Annex A defines it.** It was carried as a free-format `app.Raw`; it now decodes to `app.DataSetCharacteristics` and is sent with a range or index prefix like other fixed-size objects. Code that decoded g86v2 as `app.Raw` needs to switch to the new type. The upstream watch found it: DSC go-dnp3 defines it as one octet too.

### Tests

- `TestCatalog` checks every catalog entry against the codec; a wire vector and error cases cover g86v2; the upstream parsers have unit tests.

---

## v1.2.0

**Date:** 2026-10-20
**Previous release:** v1.1.0

## Summary

Several outstations behind one port or line (multi-drop), as IEEE 1815
addresses them and opendnp3 and DSC go-dnp3 serve them; and
`client.Measurements` reports every kind of point data. No breaking change.

## Changes

### Added

- **`server.Group`** (`NewGroup(servers...)`): several outstations, each a `Server` with its own link address, database, handler and options, on the same connections, serial lines or UDP sockets: `ListenAndServe`, `Serve`, `ServeConn`, `ServeUDP`, `Close`. A frame goes to the outstation it is addressed to, a broadcast to all of them, also as a master's first frame. The connection limit is the smallest `WithMaxConnections` of the servers.

### Fixed

- **An outstation could panic while splitting a response into fragments.** When a fragment was so nearly full that not even the next header without objects fitted, the packer computed -1 objects and sliced out of range, ending the outstation's goroutine for that master. It happens only for a response whose sizes meet that edge; every release before has it. The packer now starts a new fragment.
- **`Measurements` left out the time and interval (g50v4), BCD integers (g101) and unsigned integers (g102).** They are point data like any other: an application had to walk `Result.Headers` to see them, as dnp3ctl did. The other variations of group 50 (the time of time synchronization and freezes) are still not measurements.

### Tests

- `FuzzPack`: the splitting of responses into fragments, for any headers (ranges, index prefixes, octet strings, relative-time events behind a CTO) and any fragment size, with its invariants: no panic, no fragment over the size, every object kept in order, events aligned. `FuzzOutstation` also runs against an outstation with the smallest fragments and hundreds of points. Each finds the panic above within a second; neither existed when it was written.
- Interop: the masters of opendnp3, DSC go-dnp3 and dnp3py reach each of three go-dnp3 outstations behind one port by its link address; an address nobody has is not answered.
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
interop suite covers every feature the dnp3-interop v0.3.0 images offer,
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
- **Dual end point**: `server.DialAndServe` connects to the master, serves the connection and reconnects with backoff (`server.Redial`), with TLS as the TLS client; `client.Accept` makes the master wait for the outstation's connection.
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

- **Fragments received just before the peer closed were dropped.** When a connection ended, a session could stop before handing over fragments it had already received and queued. An outstation could then miss the confirmation of a response from a master that confirms and hangs up at once, and report the same events again on the next connection. The interop suite caught it intermittently against another stack's master. Queued fragments are now delivered before the session ends.

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
