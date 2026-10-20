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
- [Deviations and choices](#deviations-and-choices)
- [Verification status](#verification-status)

## Physical and network

| Item | Master | Outstation |
|------|--------|------------|
| TCP, port 20000 | ✅ | ✅ any number of connections (`WithMaxConnections`) |
| TLS | ✅ `crypto/tls` | ✅ |
| UDP | ✅ connected socket | ✅ one master per socket; `ServeUDPTo` names the master for unsolicited responses before it sends |
| Serial, any byte stream | ✅ `WithStream` | ✅ `ServeConn` |
| Dual end point (outstation dials the master) | — | — |

## Data link layer

| Item | Support |
|------|---------|
| FT3 frames, CRC per header and 16-octet block | ✅ encode and decode, 1..250 octets of user data |
| Resynchronisation after damage | ✅ skip to start octets, step through a bad header, drop a frame with a bad data CRC |
| Addresses 0..0xFFEF, broadcast 0xFFFD..0xFFFF | ✅; masters ignore broadcasts, broadcasts carry only user data |
| Self address 0xFFFC | ✅ outstation, `WithSelfAddress` |
| UNCONFIRMED_USER_DATA | ✅ default |
| CONFIRMED_USER_DATA with RESET_LINK_STATES and the frame count bit | ✅ both roles (`Link.Confirmed`); repeats discarded by FCB; NACK resets the link once |
| TEST_LINK_STATES | ✅ answered; FCB toggled when expected |
| REQUEST_LINK_STATUS / LINK_STATUS | ✅ answered; sent as keep-alive (`Link.KeepAlive`, default 60 s) |
| Primary frame timeout and retries | ✅ `Link.Timeout`, `Link.Retries` |
| DFC (data flow control) | sent as 0; ignored on receipt |
| FCV checked against the function | ✅ frames with an invalid FCV are ignored |
| Multi-drop: several associations on one channel | ✅ internally; the public client serves one outstation |

## Transport function

| Item | Support |
|------|---------|
| Segments of 249 octets, FIR/FIN, six-bit sequence | ✅ |
| Reassembly rules of clause 8.2.1.2 | ✅ FIR restarts, a gap discards the fragment, a non-FIR outside a fragment is discarded |
| Fragment size | 2048 by default, at least 249 (`WithMaxFragment`) |

## Application layer

| Item | Master | Outstation |
|------|--------|------------|
| Requests of one fragment | ✅ | ✅ |
| Responses of several fragments with confirmation | ✅ receives, confirms each | ✅ sends, waits for each confirmation |
| Application confirmation of events | ✅ | ✅ events removed on confirmation, reported again otherwise |
| Unsolicited responses, UNS confirmation | ✅ confirms, ignores repeats | ✅ |
| Sequence numbers: solicited and unsolicited spaces | ✅ | ✅ |
| Repeated request (same sequence and octets) | — | ✅ answered with the previous response, not executed again; READ executed again |
| Multi-fragment requests | — not sent | — ignored |
| Maximum objects per control request | — | `WithMaxControls`, default 16; more get TOO_MANY_OBJS |

## Function codes

| Code | Function | Master | Outstation |
|-----:|----------|:------:|:----------:|
| 0 | CONFIRM | ✅ | ✅ |
| 1 | READ | ✅ | ✅ |
| 2 | WRITE | ✅ | ✅ time, IIN, deadbands, attributes, octet strings, file blocks |
| 3, 4 | SELECT, OPERATE | ✅ | ✅ |
| 5, 6 | DIRECT_OPERATE, _NR | ✅ | ✅ |
| 7..10 | IMMED_FREEZE, FREEZE_CLEAR, _NR | ✅ | ✅ counters and analog inputs |
| 11, 12 | FREEZE_AT_TIME, _NR | ✅ | partly: a time that has passed, no interval |
| 13, 14 | COLD_RESTART, WARM_RESTART | ✅ | ✅ with `RestartHandler` |
| 15..19 | INITIALIZE_DATA, INITIALIZE_APPL, START_APPL, STOP_APPL, SAVE_CONFIG | `Request` | ✅ with `ApplicationHandler` |
| 20, 21 | ENABLE_UNSOLICITED, DISABLE_UNSOLICITED | ✅ | ✅ with `WithUnsolicited` |
| 22 | ASSIGN_CLASS | ✅ | ✅ |
| 23 | DELAY_MEASURE | ✅ | ✅ |
| 24 | RECORD_CURRENT_TIME | ✅ | ✅ |
| 25..30 | OPEN_FILE, CLOSE_FILE, DELETE_FILE, GET_FILE_INFO, AUTHENTICATE_FILE, ABORT_FILE | ✅ | ✅ with `WithFileServer` |
| 31 | ACTIVATE_CONFIG | `Request` | ✅ with `ApplicationHandler` |
| 32, 33 | AUTHENTICATE_REQ, AUTH_REQ_NO_ACK | ✅ | ✅ with `WithSecureAuthentication` |
| 129, 130, 131 | RESPONSE, UNSOLICITED_RESPONSE, AUTHENTICATE_RESP | ✅ | ✅ |

Any other code is answered with NO_FUNC_CODE_SUPPORT.

## Objects

The codec decodes and encodes every variation below, in every qualifier
the standard allows for it (start-stop 0x00..0x02, virtual 0x03..0x05, all
0x06, count 0x07..0x09, index-prefixed 0x17/0x28/0x39, free-format
0x4B/0x5B/0x6B). The outstation's database serves the point types; the
others are used by the procedures.

| Groups | Objects | Outstation database |
|--------|---------|---------------------|
| 1, 2 | binary input, events v1..v3 (relative time with CTO) | ✅ |
| 3, 4 | double-bit binary input, events v1..v3 | ✅ |
| 10, 11 | binary output status, events | ✅ |
| 12 | CROB, pattern control block, pattern mask | controls |
| 13 | binary output command events | codec |
| 20, 22 | counters, events, all variations (delta included) | ✅ |
| 21, 23 | frozen counters, events | ✅ |
| 30, 32 | analog inputs, events, integer and floating point | ✅ |
| 31, 33 | frozen analog inputs, events | ✅ |
| 34 | analog input deadbands | ✅ written by the master |
| 40, 42 | analog output status, events | ✅ |
| 41 | analog output blocks | controls |
| 43 | analog output command events | codec |
| 50 | time and date v1..v4 | time synchronization, freeze at time |
| 51 | CTO, synchronized and unsynchronized | relative-time events |
| 52 | time delay, coarse and fine | restart, delay measurement |
| 60 | class objects | polls, unsolicited control, assign class |
| 70 | file control v1 (raw), v2..v8 | file transfer |
| 80 | internal indications | read, clear of DEVICE_RESTART |
| 0 | device attributes, all data types, the list of variations | ✅ `WithAttributes` |
| 101, 102 | BCD integers, unsigned 8-bit integer | codec |
| 110, 111 | octet strings, events | ✅ |
| 112, 113 | virtual terminal | codec |
| 120 | authentication v1..v15 | secure authentication |
| 121, 122 | security statistics, events | codec |
| 83, 85..88, 90, 91 | private registration, data sets, application identifier, status of requested operation | raw payload |

Default variations of the outstation (configurable per point): static
g1v2, g3v2, g10v2, g20v1, g21v1, g30v1, g31v1, g40v1, g110; events g2v2,
g4v2, g11v2, g22v5, g23v5, g32v3, g33v3, g42v3, g111.

A read of a packed variation (g1v1, g3v1, g10v1) reports a point whose
flags are not ONLINE alone in the variation with flags, so that its quality
is not lost, as the reference outstations do.

## Procedures

| Procedure | Master | Outstation |
|-----------|--------|------------|
| Integrity poll, event poll, read of ranges, index lists, counts | ✅ | ✅ |
| Event reporting in time order across types | ✅ | ✅ per-master buffers, limits per type, oldest discarded with overflow |
| Event deadbands | ✅ writes g34 | ✅ per point (`PointConfig.Deadband`) for analog and counter points; analog input deadbands writable by the master (g34) |
| Unsolicited: null response at connection, enable/disable per class, hold time and count, retries, retry delay | ✅ | ✅ classes survive connections |
| Select-before-operate: same objects, next sequence number, select timeout | ✅ | ✅ |
| Direct operate, no-ack, pattern control | ✅ | ✅ |
| Time synchronization, LAN and non-LAN procedures | ✅ automatic on NEED_TIME | ✅ NEED_TIME at start and after an interval |
| Restart, delay announced | ✅ | ✅ |
| Clear of DEVICE_RESTART | ✅ automatic | ✅ |
| Freeze, freeze-and-clear | ✅ | ✅ unchanged frozen values produce no event |
| Assign class | ✅ | ✅ |
| File transfer: read, write, directory, info, delete, authenticate, abort | ✅ | ✅ |
| Device attributes | ✅ | ✅ |
| Broadcast | — not sent | ✅ executed without a response, IIN1.0 in the next one |

## Secure Authentication

Version 5, clause 7. Update keys are configured on both ends; session
keys are negotiated by the session key change, or, without an update key,
a pre-shared session key is used directly.

| Item | Support |
|------|---------|
| Challenge of critical requests (g120v1), reply (g120v2) | ✅ both roles |
| Critical function codes | `server.DefaultCritical`, configurable |
| MAC algorithms | HMAC-SHA-256 truncated to 8 and 16, HMAC-SHA-1 truncated to 4, 8 and 10 |
| Authentication error (g120v7) | ✅ sent on a wrong MAC, reported as `*dnp3.AuthError` |
| Session key status request and status (g120v4, v5) | ✅ both roles: fresh challenge data per status, MAC over the last key change with the monitoring key |
| Session key change (g120v6), AES-128 and AES-256 key wrap (RFC 3394) | ✅ both roles: at every connection and at the key change interval (`client.WithKeyChangeInterval`, default 15 minutes); keys invalid after the connection ends |
| Key status message in the key change data | the master sends the g120v5 object with its MAC value; the outstation accepts it with or without, as implementations differ |
| Update key change (g120v11..v15), user status change (g120v10), certificates (g120v8) | — objects only, procedures not implemented |
| Aggressive mode (g120v3 + g120v9) | — objects only |
| AES-GMAC | — |
| Security statistics (g121, g122) | — objects only |

## Deviations and choices

- **Multi-fragment requests** are ignored by the outstation and not sent by
  the master.
- **FREEZE_AT_TIME** with a future time or an interval is refused with
  PARAMETER_ERROR.
- **A read of an index that does not exist** is answered with the indexes
  that do and PARAMETER_ERROR.
- **Associations are per master address.** A master that reconnects from
  a new connection while its old one stands takes over: the old connection
  is closed. Events, unsolicited classes and selections belong to the
  association, not to the connection.
- **DEVICE_RESTART** is set per association when it is created, so that
  every master sees it once.

## Verification status

| Level | Status |
|-------|--------|
| Codec unit tests, known vectors, round trip of every variation and qualifier | ✅ |
| Fuzzing: link frame decoder, stream reader, transport reassembly, application fragment decoder with stable re-encoding | ✅ in CI |
| Link procedures frame by frame; noisy and duplicating lines | ✅ |
| Outstation conformance with a scripted master | ✅ |
| Master against outstation, every function | ✅ |
| Concurrency, many masters, reconnects, cancellation, `-race` | ✅ |
| As master against stepfunc dnp3 1.7.0, opendnp3 3.1.2, DSC Systems go-dnp3 v0.8.1 outstations | ✅ `make interop`, dnp3-interop v0.1.0 |
| As outstation against the same masters and dnp3py 0.6.0 | ✅ `make interop`, dnp3-interop v0.1.0 |
| Secure Authentication against another stack | — none of the references runs it in dnp3-interop's contract 1.0; DSC Systems go-dnp3 implements a symmetric subset, the next candidate |
| File transfer against another stack | — not in dnp3-interop's contract 1.0 |
| TLS, UDP, serial against another stack | — not in dnp3-interop's contract 1.0; verified between go-dnp3's own ends |
