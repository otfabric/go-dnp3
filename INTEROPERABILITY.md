# Interoperability: otfabric/go-dnp3

What go-dnp3 implements of IEEE 1815-2012, layer by layer, in the manner
of a device profile, and how it has been verified.

## Contents

- [Physical and network](#physical-and-network)
- [Data link layer](#data-link-layer)
- [Transport function](#transport-function)
- [Application layer](#application-layer)
- [Function codes](#function-codes)
- [Objects](#objects)
- [Procedures](#procedures)
- [Secure Authentication](#secure-authentication)
- [Subset levels](#subset-levels)
- [Deviations and choices](#deviations-and-choices)
- [Verification status](#verification-status)
- [Frozen counter events](#frozen-counter-events)
- [Interop coverage](#interop-coverage)
- [Feature completeness and the remaining gaps](#feature-completeness-and-the-remaining-gaps)

## Physical and network

| Item | Master | Outstation |
|------|--------|------------|
| TCP, port 20000 (13.2.3.1) | ✅ initiating end point, any port | ✅ listening end point, any port, any number of connections (`WithMaxConnections`) |
| TLS (7.8.8, 13.2.2.2) | ✅ `crypto/tls` | ✅; `ListenAndServe("")` with `WithTLS` listens on 19999 (`DefaultTLSPort`) |
| UDP (13.2.3.2) | ✅ connected socket (`UDP`), from a given local port (`UDPFrom`), through a caller's dialer (`UDPWithDialer`); every frame of a datagram is decoded | ✅ one master per socket. Table 13-1 case 2, reply to the request's port: `ServeUDP`, `ServeUDPTo`; case 1, a fixed master port: `ServeUDPFixed`. While the master is on TCP, its broadcasts over UDP are taken without disturbing the TCP connection |
| Serial, any byte stream | ✅ `WithStream` | ✅ `ServeConn` |
| Dual end point (13.2.3.1.3) | ✅ `WithDualEndpoint`: dials the outstation and takes the outstation's connections, one connection at a time, the master's own first, with address validation; `client.Accept` only listens, again after each loss with `WithReconnect` | ✅ `DialAndServe`: connects, serves, reconnects with backoff and optional jitter (`Redial`), through the dialer of `server.WithDialer`, and does not dial while the master is connected; TLS with the outstation as TLS client |
| A second connection of a connected master (13.2.3.3) | — | ✅ rejected while the first answers a link status request; a broken first connection is replaced, and the requests the new connection sent meanwhile are answered |
| Keep-alive (13.2.3.3.1) | ✅ `Link.KeepAlive`, default 60 s, any positive duration; disabling it is for testing | ✅ the same; a TCP connection on which no master sends a frame within one interval and the link timeout is closed |
| IP address validation (13.2.3.1.4, 13.2.3.2.2 d, 13.3.1) | ✅ `allow` of `WithDualEndpoint` | ✅ `WithMasterIPs`, TCP and UDP |
| Multiple masters (13.2.3.5) | — | ✅ per master address on one listener; method 1, by the master's IP address: `ServeByMasterIP`; method 2, a port per master: a listener per `Server` or `Group` |

## Data link layer

| Item | Support |
|------|---------|
| FT3 frames, CRC per header and 16-octet block | ✅ encode and decode, 1..250 octets of user data |
| Resynchronisation after damage | ✅ skip to start octets, step through a bad header, drop a frame with a bad data CRC |
| Addresses 0..0xFFEF, broadcast 0xFFFD..0xFFFF | ✅; the master sends broadcasts with `Client.Broadcast` and drops those it receives, as clauses 4 to 6 define broadcast only for requests; broadcasts carry only user data |
| Self address 0xFFFC (9.2.5.2.2) | ✅ outstation, opt-in with `WithSelfAddress`; the master never takes it |
| Reserved addresses 0xFFF0..0xFFFB | ✅ not answered |
| DIR bit (9.2.4.1.3.1) | ✅ set on transmission, ignored on receipt |
| UNCONFIRMED_USER_DATA | ✅ default |
| CONFIRMED_USER_DATA with RESET_LINK_STATES and the frame count bit | ✅ both roles (`Link.Confirmed`), for serial links: 13.2.1.1 forbids it over IP, and a channel on TCP or UDP with it logs a warning. Repeats are acknowledged and discarded by FCB; NACK with DFC 0 resets the link once |
| TEST_LINK_STATES | ✅ answered; FCB toggled when expected; a repeat is answered with the previous ACK or NACK (9.2.6.2, Table 9-7). The primary does not send it |
| REQUEST_LINK_STATUS / LINK_STATUS | ✅ answered; sent as keep-alive (`Link.KeepAlive`, default 60 s); any secondary answer shows the link alive, one other than LINK_STATUS is logged as an error (Table 9-6) |
| Primary frame timeout and retries | ✅ `Link.Timeout`, `Link.Retries` |
| DFC (data flow control, 9.2.4.1.3.5) | ✅ set while the receive queue is full; CONFIRMED_USER_DATA that would overflow it is answered NACK; a NACK with DFC set is not repeated (Table 9-6 row 28) |
| Function codes the standard does not define (such as the obsolete 1, reset of user process) | ignored, no answer: frames are dropped as framing errors. The DNP3 IED certification procedure 6.6.2.2 accepts no answer or a NACK; the recorded run of that procedure against the opendnp3 outstation (testdata/captures) is replayed against go-dnp3's with the same result |
| FCV checked against the function | ✅ frames with an invalid FCV are ignored |
| Multi-drop: several outstations on one channel | ✅ master: one `Client` per outstation, each with its own connection (TCP, UDP); the client has no channel shared by several outstations on one serial line. Outstation: `server.Group`, several `Server`s, each at its own address, on the same connections, serial lines and UDP sockets; broadcasts reach all of them |

## Transport function

| Item | Support |
|------|---------|
| Segments of 1 to 249 octets of fragment data (250 with the transport header), FIR/FIN, six-bit sequence (8.2.2) | ✅; a segment without data is rejected |
| Reception rules of 8.2.1.4 and Table 8-1 | ✅ FIR restarts, a repeat of the previous segment is discarded and the fragment goes on, any other sequence error discards the fragment, a non-FIR outside a fragment is discarded |
| Fragment size | 2048 received by default, at least 249 (`WithMaxFragment`; below 2048 is outside 4.3 Rule 3); requests unlimited, or at most n ≥ 249 with the client's `WithMaxRequestFragment` |

## Application layer

| Item | Master | Outstation |
|------|--------|------------|
| Requests of one fragment | ✅ | ✅ |
| Responses of several fragments with confirmation | ✅ receives, confirms each fragment that asks for it (CON) once it has parsed the whole fragment: one whose parse stopped early is dropped unconfirmed, so that the outstation keeps its events; `WithSolicitedConfirm(false)` confirms none, for tests and diagnostics only (such a response stalls after its first fragment); a repeat of the last fragment is confirmed again; any other unexpected fragment abandons the response (Table 6-2) | ✅ sends, waits for each confirmation |
| Application confirmation of events | ✅ | ✅ events removed on confirmation, reported again otherwise |
| Unsolicited responses, UNS confirmation | ✅ confirms those that ask for it and parsed whole, at once and before the next request; a repeat (same SEQ and octets after the IIN) is confirmed again, not processed, unless it reports a restart; same SEQ with new content is processed and followed by an integrity poll (4.6.6 Rule 7); a fragment whose UNS bit contradicts its function code is ignored; `WithUnsolicitedConfirm(false)` confirms none, for tests and diagnostics only | ✅ |
| Sequence numbers: solicited and unsolicited spaces | ✅ | ✅ |
| Repeated request (same sequence and octets) | — | ✅ answered with the previous response, not executed again; a READ is executed again, except while the confirmation of its response is awaited, when the response is sent again (Table 6-1 row 17) |
| Multi-fragment requests, requests with UNS set | — not sent | — discarded without a response (4.3 Rule 4, 4.2.2.4.4) |
| Requests with CON set | — not sent | ✅ confirmed (4.3 Rule 12) |
| Maximum objects per control request | — | `WithMaxControls`, default 16; more get TOO_MANY_OBJS |

## Function codes

| Code | Function | Master | Outstation |
|-----:|----------|:------:|:----------:|
| 0 | CONFIRM | ✅ | ✅ |
| 1 | READ | ✅ | ✅ |
| 2 | WRITE | ✅ | ✅ time, IIN, deadbands, attributes, octet strings, file blocks |
| 3, 4 | SELECT, OPERATE | ✅ | ✅ |
| 5, 6 | DIRECT_OPERATE, _NR | ✅ | ✅ |
| 7..10 | IMMED_FREEZE, FREEZE_CLEAR, _NR | ✅ | ✅ counters and analog inputs; FREEZE_CLEAR of analog inputs is answered IIN2.1 (Table 12-14) |
| 11, 12 | FREEZE_AT_TIME, _NR | ✅ 11; 12 with `Request` | ✅ per Table 4-11: time 0 and interval 0 at once; a time to come once; time 0 with an interval every interval from the start of the current hour; a time and an interval every interval from that time; the time all ones cancels. A time that has passed without an interval is refused (A.23.2). A new FREEZE_AT_TIME for the same point headers replaces the schedule (up to `MaxScheduledFreezes` waiting). Scheduled freezes belong to the `Server`, not to one master: restarts and reconnections leave them waiting, `Close` stops them |
| 13, 14 | COLD_RESTART, WARM_RESTART | ✅ | ✅ with `RestartHandler` |
| 15..19 | INITIALIZE_DATA, INITIALIZE_APPL, START_APPL, STOP_APPL, SAVE_CONFIG | `Request` | ✅ with `ApplicationHandler`; SAVE_CONFIG answered with g52v2; IIN2.4 passed on. INITIALIZE_DATA is obsolete (4.4.10): without a handler, and with one that returns IIN2.0, it is answered IIN2.0 |
| 20, 21 | ENABLE_UNSOLICITED, DISABLE_UNSOLICITED | ✅ | ✅ with `WithUnsolicited` |
| 22 | ASSIGN_CLASS | ✅ | ✅ also command events (g12v0, g41v0); security statistics to class 0 IIN2.0 |
| 23 | DELAY_MEASURE | ✅ | ✅ timed from the delivery of the fragment; above 65535 ms answered 65535 |
| 24 | RECORD_CURRENT_TIME | ✅ | ✅ |
| 25..30 | OPEN_FILE, CLOSE_FILE, DELETE_FILE, GET_FILE_INFO, AUTHENTICATE_FILE, ABORT_FILE | ✅ | ✅ with `WithFileServer` |
| 31 | ACTIVATE_CONFIG | ✅ `ActivateConfig`, returns the g91v1 status | ✅ with `ActivateConfigHandler`, answered with one g91v1 object (qualifier 0x07); with `ApplicationHandler`, the same g91v1 object with its IIN |
| 32, 33 | AUTHENTICATE_REQ, AUTH_REQ_NO_ACK | ✅ 32; 33 not sent | ✅ with `WithSecureAuthentication` |
| 129, 130, 131 | RESPONSE, UNSOLICITED_RESPONSE, AUTHENTICATE_RESP | ✅ | ✅ |

Any other code is answered with NO_FUNC_CODE_SUPPORT.

## Objects

The codec decodes and encodes every variation below, in every qualifier
the standard allows for it (start-stop 0x00..0x02, virtual 0x03..0x05, all
0x06 (requests only), count 0x07..0x09, index-prefixed 0x17..0x19, 0x27..0x29, 0x37..0x39, free-format
0x4B/0x5B/0x6B). The outstation's database serves the point types; the
others are used by the procedures. [OBJECTS.md](OBJECTS.md) lists each
variation with its size and whether it is point data, generated from the
catalog `app/catalog.json`, whose sizes are compared weekly with those of
DSC go-dnp3. Group 100 is not decoded: IEEE 1815-2012 A.38 defines no
coding for its variations, and a response that carries it does not decode.

| Groups | Objects | Outstation database |
|--------|---------|---------------------|
| 1, 2 | binary input, events v1..v3 (relative time with CTO) | ✅ |
| 3, 4 | double-bit binary input, events v1..v3 | ✅ |
| 10, 11 | binary output status, events | ✅ |
| 12 | CROB, pattern control block, pattern mask | controls |
| 13 | binary output command events | ✅ for outputs with `CommandEventClass`: every executed OPERATE, DIRECT OPERATE (NO ACK) with the commanded state and status |
| 20, 22 | counters, events, all variations (delta included) | ✅ |
| 21, 23 | frozen counters, events | ✅ |
| 30, 32 | analog inputs, events, integer and floating point | ✅ |
| 31, 33 | frozen analog inputs, events | ✅ |
| 34 | analog input deadbands | ✅ written by the master, read back (v1, v2 or v3, the smallest that holds the value unless one is asked for) |
| 40, 42 | analog output status, events | ✅ |
| 41 | analog output blocks | controls |
| 43 | analog output command events | ✅ as group 13, with the commanded value |
| 50 | time and date v1..v4 | time synchronization, freeze at time; v4 ✅ (`TimeAndInterval`, read by group and variation, not in class 0) |
| 51 | CTO, synchronized and unsynchronized | relative-time events |
| 52 | time delay, coarse and fine | restart, delay measurement |
| 60 | class objects | polls, unsolicited control, assign class |
| 70 | file control v1 (raw), v2..v8 | file transfer |
| 80 | internal indications | read, clear of DEVICE_RESTART |
| 81, 82 | device storage buffer fill status (g81v1), device profile (g82v1) | codec: g81v1 as `app.BufferFillStatus`, g82v1 as `app.Raw`; not served by the outstation |
| 0 | device attributes, all data types, the list of variations | ✅ `WithAttributes` (set 0), `WithAttributeSet` (other sets, writable variations) |
| 101, 102 | BCD integers, negative values included (sign character 0xA..0xF, sent as 0xF), unsigned 8-bit integer | codec; reported by `client.Measurements`; not served by the outstation's database |
| 110, 111 | octet strings, events | ✅ |
| 112, 113 | virtual terminal | codec |
| 120 | authentication v1..v15 | secure authentication |
| 121, 122 | security statistics, events | ✅ per association with secure authentication |
| 83, 85..88, 90 | private registration, data sets, application identifier | raw payload in the codec, except the data set characteristics g86v2 (`app.DataSetCharacteristics`, one octet) |
| 91 | status of requested operation (g91v1): time delay, count, then length, status code and text per entry | ACTIVATE_CONFIG; carried as `app.Raw`, read with `app.ParseActivateConfigStatus`. The object delimits itself, so it decodes with a count (0x07, as DSC go-dnp3 sends it and the outstation answers), range or free-format qualifier; a free-format object is carried as it is, whatever its content |

Default variations of the outstation (configurable per point): static
g1v2, g3v2, g10v2, g20v1, g21v1, g30v1, g31v1, g40v1, g50v4, g110, g121v1; events g2v2,
g4v2, g11v2, g13v2, g22v5, g23v5, g32v3, g33v3, g42v3, g43v3, g111, g122v2.

A read of a variation without flags (the packed g1v1, g3v1, g10v1, and
g20v5/v6, g21v9/v10, g30v3/v4) reports a point whose flags are not ONLINE
alone in the variation with flags, so that its quality is not lost, as the
reference outstations do. The master reads values of the variations without
flags as ONLINE (11.6.5).

## Procedures

| Procedure | Master | Outstation |
|-----------|--------|------------|
| Integrity poll, event poll, read of ranges, index lists, counts | ✅ | ✅ an event header with a count qualifier (0x07..0x09: g60v2..v4 or an event group) returns at most that many events, the oldest first, and a count of 0 none; the rest stay buffered and indicated (IIN1.1..1.3). A read of an event group returns the events of that group in every class, in the variation asked for (g2v3 and g4v3 after a CTO), and leaves the others buffered. An event header with a range or index qualifier is taken as all events of its group |
| Event reporting in time order across types | ✅ | ✅ per-master buffers, limits per type, oldest discarded with overflow |
| Event deadbands | ✅ writes and reads g34 | ✅ per point (`PointConfig.Deadband`) for analog and counter points; analog input deadbands written and read by the master (g34) |
| Unsolicited: null response at connection, enable/disable per class, hold time and count, retries, retry delay | ✅ ENABLE_UNSOLICITED again after an outstation restart (5.1.1.1.2 Rule 2) | ✅ classes survive connections; the null response is retried until confirmed; DISABLE_UNSOLICITED ends a pending series; a READ received while a confirmation is awaited is answered after it (4.6.6 Rule 16) |
| Select-before-operate: same objects, next sequence number, select timeout | ✅ OPERATE only after an echo equal to the request octet for octet (4.4.4.3 Rule 8), next sequence number, not retried | ✅ NO_SELECT, or TIMEOUT once the select timeout has passed; any other request, or a failed SELECT, ends the selection; a SELECT with the sequence number of the selection and other objects is discarded; NOT_SUPPORTED with IIN2.2; NON_PARTICIPATING (126) in a request echoed (Table 11-7 note a); FORMAT_ERROR for another request status (TB2014-002); NOT_SUPPORTED for a CROB with the queue bit (A.8.1.2.2) |
| Direct operate, no-ack, pattern control | ✅ | ✅ |
| Time synchronization, LAN and non-LAN procedures | ✅ automatic on NEED_TIME by default: LAN over TCP/TLS/UDP, non-LAN over other streams, non-LAN when the outstation refuses LAN; or clears IIN1.4 (`TimeSyncClearNeedTime`); always UNCONFIRMED_USER_DATA (10.3.4.1) | ✅ NEED_TIME at start and after an interval, of the device clock: a time written by one master clears it for all; a master may clear it with WRITE g80v1 index 4 |
| Restart, delay announced | ✅ | ✅ |
| Clear of DEVICE_RESTART | ✅ automatic, once, first in the restart procedure (after the session key change); at connect right after DISABLE_UNSOLICITED | ✅ |
| Master startup and restart procedures (5.1.1.2 Rule 1, 5.1.1.1.2 Rule 2) | ✅ startup: session keys, DISABLE_UNSOLICITED, clear IIN1.7, time, integrity poll, ENABLE_UNSOLICITED; restart: session keys, clear IIN1.7, time, integrity poll, ENABLE_UNSOLICITED | — |
| Freeze, freeze-and-clear | ✅ | ✅ a frozen counter or frozen analog input with an event class raises an event at every freeze, also for an unchanged value (11.9.5.2, 11.9.1.2; see [Frozen counter events](#frozen-counter-events)) |
| Assign class | ✅ | ✅ a point without an event class follows its value, so that once ASSIGN_CLASS gives it a class, the next event reports a change from the value the master reads |
| File transfer: read, write, append (`FileOptions.Append`), directory, info, delete, authenticate, abort | ✅ | ✅ an open file no request names for `WithFileTimeout` (default 5 minutes) is closed and reported with a g70v6 HANDLE_EXPIRED event; handles are unique to the outstation; status codes per Table 11-8 |
| Device attributes | ✅ | ✅ |
| Broadcast | ✅ `Broadcast` to 0xFFFD, 0xFFFE or 0xFFFF, for the requests that need no answer | ✅ executed without a response, also as a master's first frame; IIN1.0 in the next response; after a broadcast to 0xFFFE or 0xFFFF that response asks for confirmation, and IIN1.0 is reported until it comes; a CONFIRM sent to a broadcast address is ignored |

## Secure Authentication

Version 5, clause 7. Update keys are configured on both ends; session
keys are negotiated by the session key change, or, without an update key,
a pre-shared session key is used directly (outside the standard, see
[Deviations and choices](#deviations-and-choices)).

| Item | Support |
|------|---------|
| Challenge of critical requests (g120v1), reply (g120v2) | ✅ both roles: 32 octets of challenge data, user number 0; the reply and the response keep the sequence number of the critical request; the outstation discards other requests while a challenge waits (Table 7-8); the master answers a challenge of a no-ack request and of a CONFIRM |
| Critical function codes | `secauth.DefaultCritical` (`server.DefaultCritical` is the same slice), configurable, always including the MANDATORY codes of Table 7-7 (`secauth.MandatoryCritical`); also the default set of `client.WithAggressiveMode` |
| MAC algorithms | HMAC-SHA-256 truncated to 8 and 16, HMAC-SHA-1 truncated to 4, 8 and 10. The outstation challenges with the algorithm of its `secauth.User`; the master answers with the algorithm the challenge names and uses it for aggressive mode, among those `client.WithChallengeMACs` allows (by default all but the obsolete HMAC-SHA-1/4, and over TCP/UDP not the 8-octet truncations, clause 7.6.1.1) |
| Authentication error (g120v7) | ✅ sent on a wrong MAC, up to Max Error Messages Sent until the next key change (clause 7.5.2.4), reported as `*dnp3.AuthError` |
| Session key status request and status (g120v4, v5) | ✅ both roles: fresh challenge data per status, MAC over the last key change with the last monitoring key, also for COMM_FAIL after a reconnect; the master checks it; unknown user answered AUTH_FAIL |
| Session key change (g120v6), AES-128 and AES-256 key wrap (RFC 3394) | ✅ both roles: at every connection, at the key change interval (`client.WithKeyChangeInterval`, default 15 minutes, can be off) and after the key change count (`client.WithKeyChangeCount`, default 1000), after an outstation restart and after an authentication error (each at most 3 times in a row); the outstation invalidates keys after the connection ends, past Max Reply Timeouts or Max Authentication Failures, and after the expected interval (30 minutes) or count (2000) |
| Key status message in the key change data | the master sends the g120v5 object without its MAC value, the form DSC go-dnp3 requires; the outstation accepts it with or without, as implementations differ |
| Aggressive mode (g120v3 + g120v9) | ✅ both roles: the master (`client.WithAggressiveMode`) puts a MAC over the last challenge and the request up to the MAC value (Table A-9) into the request, once a challenge was answered since the key change; the outstation executes it without a challenge when the CSQ follows the last one, and refuses it with error 4 when `SecureAuth.NoAggressiveMode` is set. Verified between go-dnp3's ends only: no reference in dnp3-interop implements it |
| Reply timeout | ✅ `SecureAuth.ReplyTimeout`, default 2 s: the challenged request is then discarded and counted |
| Security statistics (g121, g122) | ✅ outstation: the 18 statistics of clause 7.6 per association, Association ID 0, read as g121v1, reported as g122v2 events in `StatisticsClass` at the thresholds of Table 7-6 (`SecureAuth.Thresholds`, or `StatisticsThreshold` for all); the statistics of procedures go-dnp3 does not implement stay 0 (authorization failures, update key changes and their failures, critical messages sent by the outstation); master: `Client.SecurityStatistics`, and read like any object from the outstation |
| Update key change (g120v11..v15), user status change (g120v10), certificates (g120v8) | — objects only, procedures not implemented (see [the gaps](#feature-completeness-and-the-remaining-gaps)) |
| AES-GMAC | — (see [the gaps](#feature-completeness-and-the-remaining-gaps)) |
| Challenges of critical responses (master challenging the outstation) | — |

### Secure Authentication device profile

- **Session key generation**: the master draws session keys from the
  operating system's cryptographic random number generator (Go
  `crypto/rand`), as long as the update key (16 or 32 octets).
- **Challenge data**: 32 octets from the same generator. It is a
  cryptographically secure generator, not the FIPS 186-2 algorithm
  A.45.1.2.2 names.
- **Critical function codes**: `secauth.DefaultCritical`, always including
  the MANDATORY codes of Table 7-7.
- **Users**: one user per association (`secauth.User`); user number 1
  unless configured.
- **Defaults** (clause 7.6): reply timeout 2 s, key change interval 15
  min, key change count 1000, expected key change interval 30 min and
  count 2000, maximum session key status count 5, statistic thresholds as
  Table 7-6.
- **MAC algorithms**: HMAC-SHA-256 and HMAC-SHA-1; 8-octet truncations on
  serial links only by default for the master.
- **Key wrap**: AES-128 and AES-256 (RFC 3394); no AES-GMAC, no update key
  change.

## Subset levels

A go-dnp3 master declares no subset level. Its default requests are within
Level 1: the integrity poll (class 1, 2, 3, 0), the clear of IIN1.7 (g80v1
qualifier 0x00), and the non-LAN time synchronization (DELAY_MEASURE and
WRITE g50v1). Two defaults are above Level 2:

- a `SetPoint` without `Command.GV` is sent as g41v1 (Level 3 and up) or
  g41v3 (Level 4); Levels 1 and 2 define only g41v2 (Tables 14-2 and
  14-3), so set `Command.GV` to `app.G41V2` for them;
- over TCP, TLS and UDP the automatic time synchronization uses the LAN
  procedure (RECORD_CURRENT_TIME and WRITE g50v3), which is Level 4
  (Table 12-32). An outstation that refuses it with IIN2.0 or IIN2.1 is
  synchronized with the non-LAN procedure from then on.
  `WithTimeSync(client.TimeSyncNonLAN)` uses the non-LAN procedure from
  the start.

The master parses every object and qualifier of the Level 1 to 3 response
columns (Tables 14-2 to 14-4), in responses and unsolicited responses:
`TestSubsetLevelResponses`.

The outstation declares no subset level either (see
[LIMITATIONS.md](LIMITATIONS.md#conformance-and-certification)); every
request row of Tables 14-2 to 14-4 is answered without an error IIN:
`TestSubsetLevelTables`.

## Deviations and choices

- **Multi-fragment requests**, which the standard's application layer does
  not allow, are ignored by the outstation and never sent by the master: a
  request is one fragment (DSC go-dnp3 refuses them as well).
- **Pre-shared session keys.** Without an update key, `secauth.User.Key` is
  used as the session key with no session key change. This is outside
  SAv5, which always sets session keys by the key change, and works only
  between go-dnp3 ends or a peer configured the same way; it is meant for
  testing (see [SECURITY.md](SECURITY.md)).
- **No critical request without session keys.** A master with an update
  key does not send a function Table 7-7 marks MANDATORY, or one
  `WithAggressiveMode` names, while its session keys are not valid: the
  request fails with `dnp3.ErrAuthentication`, unsent, and the keys are
  changed. Sent, it could only fail, since the master discards a challenge
  it has no valid keys for (Table 7-13 row 7), and it would keep the
  outstation waiting for the reply, which discards the key status request
  meanwhile (Table 7-8 row 16). Non-critical requests go on (7.3.6).
- **A read of an index that does not exist** is answered with the indexes
  that do and PARAMETER_ERROR.
- **Associations are per master address.** A master that connects again
  while its old connection stands is rejected when the old one answers a
  link status request, and replaces it when it does not (13.2.3.3, NOTE
  2). Events, unsolicited classes and selections belong to the
  association, not to the connection.
- **DEVICE_RESTART** is set per association when it is created, so that
  every master sees it once.
- **`Unsolicited.Classes`** enables unsolicited reporting of those classes
  at startup, before an ENABLE_UNSOLICITED. IEEE 1815-2012 5.1.1.1.1
  Rule 3 (p. 101) and 4.4.13 (p. 60) do not allow it; it is for masters
  that never send ENABLE_UNSOLICITED. The default, no classes, follows
  the standard.
- **INITIALIZE_DATA** is obsolete, and new designs shall not implement it
  (4.4.10, p. 58). Without an `ApplicationHandler` it is answered IIN2.0;
  a handler receives it and should answer IIN2.0.
- **A repeated READ** is executed again when no confirmation is awaited,
  as Table 6-1 allows.
- **IIN1.1 to IIN1.3** do not count the events of an unsolicited response
  that awaits its confirmation: they are reported. 4.5.2 (p. 82) does not
  settle this.
- **DELAY_MEASURE** is timed from the delivery of the request fragment,
  not from the arrival of its first octet (4.4.15.1).
- **Open with maximum block size 0** is answered with the outstation's
  block size: the text (4.4.17.2.2) does not cover 0, and masters use it
  for "no preference".
- **FILE_FATAL in g70v4**: an open of a file the outstation cannot serve
  and a failed close are answered FATAL (19), which Table 11-8 lists for
  those functions and A.27.4 does not.
- **Class 0 includes octet strings (g110)** unless the point is
  `ExcludeFromClass0`: A.41.1.2.3 excludes them, Table 5-1 lists group
  110 among the objects of class 0.
- **A read of a type the outstation has no points of**, static or event,
  is answered IIN2.1, as TB2016-001 and IED certification procedure
  3.1r1 expect, where Table 4-14 (p. 85) asks for a null response for
  events defined at the device's subset level. go-dnp3 declares no
  subset level.

## Verification status

| Level | Status |
|-------|--------|
| Codec unit tests, known vectors, round trip of every variation in start-stop, count, index-prefixed and free-format qualifiers | ✅ |
| Fuzzing: link frame decoder, stream reader, transport reassembly, application fragment decoder with stable re-encoding, the outstation's request handling, also with the smallest fragments (`FuzzOutstation`), the splitting of responses into fragments (`FuzzPack`) | ✅ in CI |
| Chaos: corrupted, split and delayed octets and killed connections under load, with and without secure authentication | ✅ `e2e/chaos_test.go` |
| Link procedures frame by frame; noisy and duplicating lines | ✅ |
| Outstation conformance with a scripted master | ✅ |
| Request rows of the subset level Tables 14-2 to 14-4 (levels 1 to 3), each answered without an error IIN | ✅ `TestSubsetLevelTables`; not a statement of a subset level |
| DNP Users Group IED certification procedures (dnp3c 0.2.0): 3.1 rev 1 at subset levels 2 and 3, 2.7 at level 2 | ✅ `make conformance`, against the [test outstation](internal/cmd/conformance) with dnp3-interop's dnp3c runner; not a certification |
| Master against outstation, every function | ✅ |
| Concurrency, many masters, reconnects, cancellation, `-race` | ✅ |
| As master against opendnp3 3.1.2, DSC go-dnp3 v0.8.2, dnp3py 0.6.0 and cB-Sigma dnp3 v0.3.0 outstations | ✅ `make interop`, dnp3-interop v0.11.2 |
| As outstation against the same masters and nfm-dnp3 1.0.1 | ✅ `make interop`, dnp3-interop v0.11.2; nfm-dnp3 with the exceptions under [Interop coverage](#interop-coverage) |
| TLS with mutual authentication, both roles | ✅ against opendnp3, DSC go-dnp3 and cB-Sigma dnp3, including a refused certificate of another CA |
| UDP, both roles | ✅ against opendnp3, DSC go-dnp3 and cB-Sigma dnp3; the master against opendnp3's outstation from a container on its network, as that outstation answers one fixed peer |
| Serial, both roles | ✅ against opendnp3, DSC go-dnp3 and cB-Sigma dnp3 over a pseudo-terminal bridged to TCP |
| File transfer: master | ✅ against the file servers of DSC go-dnp3 and cB-Sigma dnp3: read, write of several blocks, append, AUTHENTICATE_FILE, list, info, delete, missing files |
| File transfer: outstation | ✅ against the masters of DSC go-dnp3 (get, put, list, info, delete, authenticate; no append) and cB-Sigma dnp3 |
| Contract 1.3 (device attributes, several controls, freeze at time, analog freeze, deadbands, event buffer overflow, link confirms and keep-alive, broadcast, management, several outstations) | ✅ against every reference that has each, see [Interop coverage](#interop-coverage) |
| Secure Authentication, both roles | ✅ against DSC go-dnp3 and cB-Sigma dnp3 (HMAC-SHA-256-16, AES-128 key wrap): key change at connect, challenged controls, periodic key change in a session, a second connection, a wrong update key refused, security statistics read both ways (with cB-Sigma: read by its master); the other references do not implement it |
| Requests without a response | ✅ DIRECT OPERATE NO ACK and FREEZE AND CLEAR NO ACK as master against opendnp3 and DSC go-dnp3; as outstation from DSC go-dnp3's and dnp3py's masters |
| Dual end point, both roles, TCP and TLS | ✅ against opendnp3, DSC go-dnp3 and cB-Sigma dnp3 |
| Frozen analog inputs, command events, time and interval | ✅ as master against DSC go-dnp3's outstation; as outstation against the masters that decode them (opendnp3, DSC go-dnp3) |
| Aggressive mode | ✅ between go-dnp3's own ends; no reference in dnp3-interop has it |
| Recorded traffic of other software (182 captures: ITI ICS-Security-Tools, 140 conformance runs against the opendnp3 3.0 outstation, Zeek traces, the igbe attack data set; classes C and D, no identified hardware) | ✅ decoded and encoded back octet for octet, against Wireshark and the conformance runner's log; master and outstation replayed against the recorded peers ([testdata/captures](testdata/captures/README.md)); not a statement about any device |

## Frozen counter events

go-dnp3's outstation raises a frozen counter event (g23) or frozen analog
input event (g33) for every frozen point with an event class at every
freeze, also when the value and flags did not change, as IEEE 1815-2012
11.9.5.2 (p. 341) and 11.9.1.2 (p. 333) ask. The event carries the time
of the freeze, as g21v5, g21v6, g23v5 and g23v6 report it. Every event
stays buffered until confirmed.

This is covered by `server/freeze_test.go`,
`TestSpec11_9_1_2_FrozenAnalogEventAtEveryFreeze` and
`interop/counters_test.go` (`TestServerFrozenEventsAtEveryFreeze`).
Before v1.11.0 the outstation raised an event only for a changed value.

## Interop coverage

What `make interop` exercises against each reference, with go-dnp3 as
master (**M**, against the reference's outstation) and as outstation
(**O**, the reference's master against go-dnp3). A blank cell is a feature
the reference does not have or its dnp3-interop adapter does not expose
(its capability document says which): the suite covers everything the
images offer.

| Feature | opendnp3 3.1.2 | DSC go-dnp3 v0.8.2 | dnp3py 0.6.0 | cB-Sigma dnp3 v0.3.0 | nfm-dnp3 1.0.1 |
|---|:---:|:---:|:---:|:---:|:---:|
| Integrity poll: values and flags of every point type of the baseline fixture | M O | M O | O | M O |  |
| Reads of ranges and variations | M O | M O | O | M O | O |
| Read of all objects of a group | M O | M | O | O |  |
| Direct operate, select-before-operate, set-points, ranges, refused codes and points | M O | M O | O | M O |  |
| Direct operate no ack | M | M O | O | M O | O |
| Events, their confirmation, event polls | M O | M O | O | M O |  |
| Unsolicited responses, enable and disable | M O | M O | O | M O |  |
| Time synchronization, LAN and non-LAN | M O | M O | O | M O | O |
| Cold and warm restart with the delay | M O | M O | O | M O | O |
| Freeze and freeze-and-clear | M O | M O | O | M O | O |
| Freeze and clear no ack | M | M | O | M O | O |
| Assign class | M O | M | O | M O | O |
| TLS with mutual authentication | M O | M O | | M O |  |
| UDP | M O | M O | | M O |  |
| Serial line | M O | M O | | M O |  |
| File transfer: read, write, list, info | | M O | | M O |  |
| File transfer: delete | | M O | | M O |  |
| Secure Authentication: key change, challenges, re-key, wrong key | | M O | | M O |  |
| Security statistics, reads and g122 events | | M O | | O |  |
| Device attributes, other sets, read and write (contract 1.3) | | M O | | O |  |
| Several controls in one request, the limit per request (TOO_MANY_OBJS) | M O | M O | O | M O |  |
| FREEZE AT TIME, scheduled | | M O | O | M O | O |
| Analog freeze into frozen analog inputs | O | M | O | O | O |
| Deadbands (g34): write; read back | | M O (write) | | M O (write) | O (write) |
| File append, AUTHENTICATE_FILE | | M O | | M O |  |
| Event buffer overflow (IIN2.3) | M O | M O | M O | M O | O |
| Link confirms; keep-alive | O (keep-alive) | M O | | M (keep-alive) O |  |
| Broadcast | M | M O | | M O |  |
| Management functions (INITIALIZE, START, STOP, SAVE) | O | M | | O | O |
| Several outstations behind one port | M O | M O | O | M O | O |
| Dual end point, TCP | M O | M O | | M O |  |
| Dual end point, TLS | M O | M O | | M O |  |
| Frozen analog inputs (g31) | | M O | | O | O |
| Command events (g13, g43) | O | M O | | O |  |
| Time and interval (g50v4) | O | M | | O |  |
| The dnp3py fixture (integrity poll, a control and its target) | M | M | M | M |  |

Known bugs of a reference that the fixture shows (dnp3-interop's
`tests/known-bugs.tsv`) are logged, not failed: DSC go-dnp3 v0.8.2 leaves a
counter without a frozen counter uncleared by FREEZE AND CLEAR. One more
known bug touches the contract 1.3 tests, which avoid it: DSC go-dnp3
refuses FREEZE AT TIME with time 0 (the tests use a time to come). Four
findings about the references that the suite works with: opendnp3's UDP
outstation answers only the fixed peer it is given, so go-dnp3's master
runs in a container on its network for that test; DSC go-dnp3's
outstation answers g121 reads of variation 1 only, not variation 0; and
it, like go-dnp3, leaves g50v4 out of class 0. A fourth: when a master's first requests
cross opendnp3's startup unsolicited response, opendnp3 can send the next
unsolicited response before the confirm of the first arrives and then leave
a READ unanswered until its unsolicited confirm timeout (5 s) has passed;
the tests allow for it.

opendnp3's master refuses go-dnp3's answer to SAVE_CONFIG: the Delay Time
object (g52v2) that IEEE 1815-2012 4.4.12 requires. Its `PerformFunction`
takes only a response without objects, so the operation reports a bad
response although go-dnp3 executed the function; `TestServerManagement`
checks both. The other masters accept the answer.

nfm-dnp3 1.0.1 is a master only. go-dnp3's outstation serves it the
baseline without unsolicited responses, since it sends the application
confirm as CONFIRMED_USER_DATA and cannot confirm the null unsolicited
response. Three of its defects, reported upstream and failing it against
every outstation in dnp3-interop, skip the tests they break, with the
record: integrity polls and all-objects reads (no decoder for g3v2 and g110,
fxodell/dnp3py#10), controls (CROB codes swapped and a 1-octet 0x28 count,
#7 and #5), and event polls (the 0x28 count, #5).

cB-Sigma dnp3 v0.3.0 answers AUTHENTICATE_FILE with an empty user name and
password at offset 0. Since v1.7.0 go-dnp3's master accepts empty g70v2
strings at any offset; it still sends them at offset 12.

## Feature completeness and the remaining gaps

go-dnp3 implements the procedures of IEEE 1815-2012 listed above in both
roles, including file transfer, the dual end point and Secure
Authentication version 5 with session key change, aggressive mode and
statistics. Against the references:

| Capability | go-dnp3 | opendnp3 | DSC go-dnp3 | Triangle MicroWorks SCL |
|---|:---:|:---:|:---:|:---:|
| File transfer, outstation | ✅ | — | ✅ | ✅ |
| Time and interval (g50v4) from the outstation | ✅ | ✅ | ✅ | ✅ |
| File transfer, master | ✅ | — | ✅ | ✅ |
| SAv5 challenge-reply, session key change | ✅ | — (removed in 2016) | ✅ | ✅ |
| SAv5 aggressive mode | ✅ | — | — | ✅ |
| SAv5 security statistics | ✅ | — | ✅ | ✅ |
| SAv5 remote update key change, user management | — | — | — | ✅ |
| AES-GMAC | — | — | — | ✅ |
| Dual end point | ✅ | ✅ | ✅ | ✅ |
| Command events (g13, g43) from the outstation | ✅ | — | ✅ | ✅ |
| Virtual terminal (g112, g113), data sets (g85..g88) | — codec only | not documented | ✅ outstation data set backend, terminals | ✅ |

The Triangle MicroWorks column is from its public product descriptions;
it is not in the interop suite (its adapter is on hold in dnp3-interop),
so treat it as indicative.

The gaps, and what closing them would be worth:

- **Remote update key change and user management (g120v8, g120v10..v15).** Lets a
  central authority distribute update keys and add or revoke users,
  symmetric or with certificates (IEC 62351-8). Worth it for a utility
  that runs such an authority; elsewhere update keys are provisioned with
  the device, which go-dnp3 supports. Only Triangle MicroWorks implements
  it, so the exact wire formats could not be checked against a second
  implementation; it waits for that reference.
- **AES-GMAC.** An optional MAC algorithm; HMAC-SHA-256 is the one every
  SAv5 implementation has and the default. Low value, and like key
  management it needs a reference implementation to verify against.
- **Challenges of critical responses by the master.** SAv5 lets a master
  challenge an outstation's responses; no reference does it. Low value.
- **Virtual terminal and data sets.** Rarely used; the codec carries them,
  so an application can still exchange them with the generic request
  methods.
- **Multi-fragment requests** are not a gap: requests are one fragment.
