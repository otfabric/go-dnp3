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
- [Interop coverage](#interop-coverage)
- [Feature completeness and the remaining gaps](#feature-completeness-and-the-remaining-gaps)

## Physical and network

| Item | Master | Outstation |
|------|--------|------------|
| TCP, port 20000 | ✅ | ✅ any number of connections (`WithMaxConnections`) |
| TLS | ✅ `crypto/tls` | ✅ |
| UDP | ✅ connected socket | ✅ one master per socket; `ServeUDPTo` names the master for unsolicited responses before it sends |
| Serial, any byte stream | ✅ `WithStream` | ✅ `ServeConn` |
| Dual end point (outstation dials the master) | ✅ `client.Accept`: waits for the outstation's connection, again after each loss with `WithReconnect` | ✅ `DialAndServe`: connects, serves, reconnects with backoff (`Redial`); TLS with the outstation as TLS client |

## Data link layer

| Item | Support |
|------|---------|
| FT3 frames, CRC per header and 16-octet block | ✅ encode and decode, 1..250 octets of user data |
| Resynchronisation after damage | ✅ skip to start octets, step through a bad header, drop a frame with a bad data CRC |
| Addresses 0..0xFFEF, broadcast 0xFFFD..0xFFFF | ✅; the master sends broadcasts with `Client.Broadcast` and ignores those it receives; broadcasts carry only user data |
| Self address 0xFFFC | ✅ outstation, `WithSelfAddress` |
| UNCONFIRMED_USER_DATA | ✅ default |
| CONFIRMED_USER_DATA with RESET_LINK_STATES and the frame count bit | ✅ both roles (`Link.Confirmed`); repeats discarded by FCB; NACK resets the link once |
| TEST_LINK_STATES | ✅ answered; FCB toggled when expected |
| REQUEST_LINK_STATUS / LINK_STATUS | ✅ answered; sent as keep-alive (`Link.KeepAlive`, default 60 s) |
| Primary frame timeout and retries | ✅ `Link.Timeout`, `Link.Retries` |
| DFC (data flow control) | sent as 0; ignored on receipt |
| FCV checked against the function | ✅ frames with an invalid FCV are ignored |
| Multi-drop: several outstations on one channel | ✅ master: one `Client` per outstation, each with its own connection (TCP, UDP); the client has no channel shared by several outstations on one serial line. Outstation: `server.Group`, several `Server`s, each at its own address, on the same connections, serial lines and UDP sockets; broadcasts reach all of them |

## Transport function

| Item | Support |
|------|---------|
| Segments of up to 249 octets of fragment data (250 with the transport header), FIR/FIN, six-bit sequence | ✅ |
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
| 11, 12 | FREEZE_AT_TIME, _NR | ✅ 11; 12 with `Request` | ✅ time 0 at once; a time to come and every interval after it (up to `MaxScheduledFreezes` waiting); a time that has passed without an interval is refused (A.23.2). Scheduled freezes belong to the `Server`, not to one master: restarts and reconnections leave them waiting, `Close` stops them |
| 13, 14 | COLD_RESTART, WARM_RESTART | ✅ | ✅ with `RestartHandler` |
| 15..19 | INITIALIZE_DATA, INITIALIZE_APPL, START_APPL, STOP_APPL, SAVE_CONFIG | `Request` | ✅ with `ApplicationHandler` |
| 20, 21 | ENABLE_UNSOLICITED, DISABLE_UNSOLICITED | ✅ | ✅ with `WithUnsolicited` |
| 22 | ASSIGN_CLASS | ✅ | ✅ |
| 23 | DELAY_MEASURE | ✅ | ✅ |
| 24 | RECORD_CURRENT_TIME | ✅ | ✅ |
| 25..30 | OPEN_FILE, CLOSE_FILE, DELETE_FILE, GET_FILE_INFO, AUTHENTICATE_FILE, ABORT_FILE | ✅ | ✅ with `WithFileServer` |
| 31 | ACTIVATE_CONFIG | `Request` | ✅ with `ApplicationHandler` |
| 32, 33 | AUTHENTICATE_REQ, AUTH_REQ_NO_ACK | ✅ 32; 33 not sent | ✅ with `WithSecureAuthentication` |
| 129, 130, 131 | RESPONSE, UNSOLICITED_RESPONSE, AUTHENTICATE_RESP | ✅ | ✅ |

Any other code is answered with NO_FUNC_CODE_SUPPORT.

## Objects

The codec decodes and encodes every variation below, in every qualifier
the standard allows for it (start-stop 0x00..0x02, virtual 0x03..0x05, all
0x06, count 0x07..0x09, index-prefixed 0x17..0x19, 0x27..0x29, 0x37..0x39, free-format
0x4B/0x5B/0x6B). The outstation's database serves the point types; the
others are used by the procedures. [OBJECTS.md](OBJECTS.md) lists each
variation with its size and whether it is point data, generated from the
catalog `app/catalog.json`, whose sizes are compared weekly with those of
stepfunc dnp3 and DSC go-dnp3.

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
| 0 | device attributes, all data types, the list of variations | ✅ `WithAttributes` (set 0), `WithAttributeSet` (other sets, writable variations) |
| 101, 102 | BCD integers, unsigned 8-bit integer | codec; reported by `client.Measurements`; not served by the outstation's database |
| 110, 111 | octet strings, events | ✅ |
| 112, 113 | virtual terminal | codec |
| 120 | authentication v1..v15 | secure authentication |
| 121, 122 | security statistics, events | ✅ per association with secure authentication |
| 83, 85..88, 90, 91 | private registration, data sets, application identifier, status of requested operation | raw payload in the codec, except the data set characteristics g86v2 (`app.DataSetCharacteristics`, one octet) |

Default variations of the outstation (configurable per point): static
g1v2, g3v2, g10v2, g20v1, g21v1, g30v1, g31v1, g40v1, g50v4, g110, g121v1; events g2v2,
g4v2, g11v2, g13v2, g22v5, g23v5, g32v3, g33v3, g42v3, g43v3, g111, g122v2.

A read of a variation without flags (the packed g1v1, g3v1, g10v1, and
g20v5/v6, g21v9/v10, g30v3/v4) reports a point whose flags are not ONLINE
alone in the variation with flags, so that its quality is not lost, as the
reference outstations do.

## Procedures

| Procedure | Master | Outstation |
|-----------|--------|------------|
| Integrity poll, event poll, read of ranges, index lists, counts | ✅ | ✅ |
| Event reporting in time order across types | ✅ | ✅ per-master buffers, limits per type, oldest discarded with overflow |
| Event deadbands | ✅ writes and reads g34 | ✅ per point (`PointConfig.Deadband`) for analog and counter points; analog input deadbands written and read by the master (g34) |
| Unsolicited: null response at connection, enable/disable per class, hold time and count, retries, retry delay | ✅ | ✅ classes survive connections |
| Select-before-operate: same objects, next sequence number, select timeout | ✅ | ✅ |
| Direct operate, no-ack, pattern control | ✅ | ✅ |
| Time synchronization, LAN and non-LAN procedures | ✅ automatic on NEED_TIME | ✅ NEED_TIME at start and after an interval |
| Restart, delay announced | ✅ | ✅ |
| Clear of DEVICE_RESTART | ✅ automatic | ✅ |
| Freeze, freeze-and-clear | ✅ | ✅ unchanged frozen values produce no event |
| Assign class | ✅ | ✅ |
| File transfer: read, write, append (`FileOptions.Append`), directory, info, delete, authenticate, abort | ✅ | ✅ |
| Device attributes | ✅ | ✅ |
| Broadcast | ✅ `Broadcast` to 0xFFFD, 0xFFFE or 0xFFFF, for the requests that need no answer | ✅ executed without a response, also as a master's first frame; IIN1.0 in the next response |

## Secure Authentication

Version 5, clause 7. Update keys are configured on both ends; session
keys are negotiated by the session key change, or, without an update key,
a pre-shared session key is used directly (outside the standard, see
[Deviations and choices](#deviations-and-choices)).

| Item | Support |
|------|---------|
| Challenge of critical requests (g120v1), reply (g120v2) | ✅ both roles: 32 octets of challenge data; the reply and the response keep the sequence number of the critical request |
| Critical function codes | `secauth.DefaultCritical` (`server.DefaultCritical` is the same slice), configurable; also the default set of `client.WithAggressiveMode` |
| MAC algorithms | HMAC-SHA-256 truncated to 8 and 16, HMAC-SHA-1 truncated to 4, 8 and 10 |
| Authentication error (g120v7) | ✅ sent on a wrong MAC, reported as `*dnp3.AuthError` |
| Session key status request and status (g120v4, v5) | ✅ both roles: fresh challenge data per status, MAC over the last key change with the monitoring key |
| Session key change (g120v6), AES-128 and AES-256 key wrap (RFC 3394) | ✅ both roles: at every connection and at the key change interval (`client.WithKeyChangeInterval`, default 15 minutes); keys invalid after the connection ends |
| Key status message in the key change data | the master sends the g120v5 object without its MAC value, the form DSC go-dnp3 requires; the outstation accepts it with or without, as implementations differ |
| Aggressive mode (g120v3 + g120v9) | ✅ both roles: the master (`client.WithAggressiveMode`) puts a MAC over the last challenge and the request into the request; the outstation executes it without a challenge when the CSQ follows the last one. Verified between go-dnp3's ends only: no reference in dnp3-interop implements it |
| Reply timeout | ✅ `SecureAuth.ReplyTimeout`, default 10 s: a later reply is refused and counted |
| Security statistics (g121, g122) | ✅ outstation: the 18 statistics of clause 7.6 per association, read as g121v1, reported as g122v2 events every `StatisticsThreshold` increments in `StatisticsClass`; master: read like any object |
| Update key change (g120v11..v15), user status change (g120v10), certificates (g120v8) | — objects only, procedures not implemented (see [the gaps](#feature-completeness-and-the-remaining-gaps)) |
| AES-GMAC | — (see [the gaps](#feature-completeness-and-the-remaining-gaps)) |
| Challenges of critical responses (master challenging the outstation) | — |

## Deviations and choices

- **Multi-fragment requests**, which the standard's application layer does
  not allow, are ignored by the outstation and never sent by the master: a
  request is one fragment (DSC go-dnp3 refuses them as well).
- **Pre-shared session keys.** Without an update key, `secauth.User.Key` is
  used as the session key with no session key change. This is outside
  SAv5, which always sets session keys by the key change, and works only
  between go-dnp3 ends or a peer configured the same way; it is meant for
  testing (see [SECURITY.md](SECURITY.md)).
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
| Codec unit tests, known vectors, round trip of every variation in start-stop, count, index-prefixed and free-format qualifiers | ✅ |
| Fuzzing: link frame decoder, stream reader, transport reassembly, application fragment decoder with stable re-encoding, the outstation's request handling, also with the smallest fragments (`FuzzOutstation`), the splitting of responses into fragments (`FuzzPack`) | ✅ in CI |
| Chaos: corrupted, split and delayed octets and killed connections under load, with and without secure authentication | ✅ `e2e/chaos_test.go` |
| Link procedures frame by frame; noisy and duplicating lines | ✅ |
| Outstation conformance with a scripted master | ✅ |
| Master against outstation, every function | ✅ |
| Concurrency, many masters, reconnects, cancellation, `-race` | ✅ |
| As master against stepfunc dnp3 1.7.0, opendnp3 3.1.2, DSC go-dnp3 v0.8.1 and dnp3py 0.6.0 outstations | ✅ `make interop`, dnp3-interop v0.4.3 |
| As outstation against the same masters | ✅ `make interop`, dnp3-interop v0.4.3 |
| TLS with mutual authentication, both roles | ✅ against stepfunc, opendnp3 and DSC go-dnp3, including a refused certificate of another CA |
| UDP, both roles | ✅ against stepfunc, opendnp3 and DSC go-dnp3; the master against opendnp3's outstation from a container on its network, as that outstation answers one fixed peer |
| Serial, both roles | ✅ against stepfunc, opendnp3 and DSC go-dnp3 over a pseudo-terminal bridged to TCP |
| File transfer: master | ✅ against DSC go-dnp3's file server: read, write of several blocks, append, AUTHENTICATE_FILE, list, info, delete, missing files |
| File transfer: outstation | ✅ against the masters of stepfunc (get, put, append, list, info, authenticate) and DSC go-dnp3 (get, put, list, info, delete, authenticate; no append) |
| Contract 1.3 (device attributes, several controls, freeze at time, analog freeze, deadbands, event buffer overflow, link confirms and keep-alive, broadcast, management, several outstations) | ✅ against every reference that has each, see [Interop coverage](#interop-coverage) |
| Secure Authentication, both roles | ✅ against DSC go-dnp3 (HMAC-SHA-256-16, AES-128 key wrap): key change at connect, challenged controls, periodic key change in a session, a second connection, a wrong update key refused, security statistics read both ways; the other references do not implement it |
| Requests without a response | ✅ DIRECT OPERATE NO ACK and FREEZE AND CLEAR NO ACK as master against stepfunc, opendnp3 and DSC go-dnp3; as outstation from DSC go-dnp3's and dnp3py's masters |
| Dual end point, both roles, TCP and TLS | ✅ against stepfunc, opendnp3 and DSC go-dnp3 (stepfunc's master listens over TCP only) |
| Frozen analog inputs, command events, time and interval | ✅ as master against DSC go-dnp3's outstation; as outstation against the masters that decode them (stepfunc, opendnp3, DSC go-dnp3) |
| Aggressive mode | ✅ between go-dnp3's own ends; no reference in dnp3-interop has it |

## Interop coverage

What `make interop` exercises against each reference, with go-dnp3 as
master (**M**, against the reference's outstation) and as outstation
(**O**, the reference's master against go-dnp3). A blank cell is a feature
the reference does not have or its dnp3-interop adapter does not expose
(its capability document says which): the suite covers everything the
images offer.

| Feature | stepfunc 1.7.0 | opendnp3 3.1.2 | DSC go-dnp3 v0.8.1 | dnp3py 0.6.0 |
|---|:---:|:---:|:---:|:---:|
| Integrity poll: values and flags of every point type of the baseline fixture | M O | M O | M O | O |
| Reads of ranges and variations | M O | M O | M O | O |
| Read of all objects of a group | M O | M O | M | O |
| Direct operate, select-before-operate, set-points, ranges, refused codes and points | M O | M O | M O | O |
| Direct operate no ack | M | M | M O | O |
| Events, their confirmation, event polls | M O | M O | M O | O |
| Unsolicited responses, enable and disable | M O | M O | M O | O |
| Time synchronization, LAN and non-LAN | M O | M O | M O | O |
| Cold and warm restart with the delay | M O | M O | M O | O |
| Freeze and freeze-and-clear | M O | M O | M O | O |
| Freeze and clear no ack | M | M | M | O |
| Assign class | O | M O | M | O |
| TLS with mutual authentication | M O | M O | M O | |
| UDP | M O | M O | M O | |
| Serial line | M O | M O | M O | |
| File transfer: read, write, list, info | O | | M O | |
| File transfer: delete | | | M O | |
| Secure Authentication: key change, challenges, re-key, wrong key | | | M O | |
| Security statistics, reads and g122 events | | | M O | |
| Device attributes, other sets, read and write (contract 1.3) | M O | | M O | |
| Several controls in one request, the limit per request (TOO_MANY_OBJS) | M O | M O | M O | O |
| FREEZE AT TIME, scheduled | M O | | M O | O |
| Analog freeze into frozen analog inputs | O | O | M | O |
| Deadbands (g34): write; read back | M O | | M O (write) | |
| File append, AUTHENTICATE_FILE | O | | M O | |
| Event buffer overflow (IIN2.3) | M O | M O | M O | M O |
| Link confirms; keep-alive | O (keep-alive) | O (keep-alive) | M O | |
| Broadcast | M | M | M O | |
| Management functions (INITIALIZE, START, STOP, SAVE) | | O | M | |
| Several outstations behind one port | O | M O | M O | O |
| Dual end point, TCP | M O | M O | M O | |
| Dual end point, TLS | M | M O | M O | |
| Frozen analog inputs (g31) | O | | M O | |
| Command events (g13, g43) | O | O | M O | |
| Time and interval (g50v4) | | O | M | |
| The dnp3py fixture (integrity poll, a control and its target) | M | M | M | M |

Known bugs of a reference that the fixture shows (dnp3-interop's
`tests/known-bugs.tsv`) are logged, not failed: DSC go-dnp3 v0.8.1 leaves a
counter without a frozen counter uncleared by FREEZE AND CLEAR. Two more
known bugs touch the contract 1.3 tests, which avoid them: DSC go-dnp3
refuses FREEZE AT TIME with time 0 (the tests use a time to come), and
stepfunc's master decodes a one-octet signed attribute without its sign
(go-dnp3 sends four octets). Four
findings about the references that the suite works with: opendnp3's UDP
outstation answers only the fixed peer it is given, so go-dnp3's master
runs in a container on its network for that test; DSC go-dnp3's
outstation answers g121 reads of variation 1 only, not variation 0; and
it, like go-dnp3, leaves g50v4 out of class 0. A fourth: when a master's first requests
cross opendnp3's startup unsolicited response, opendnp3 can send the next
unsolicited response before the confirm of the first arrives and then leave
a READ unanswered until its unsolicited confirm timeout (5 s) has passed;
the tests allow for it.

## Feature completeness and the remaining gaps

go-dnp3 implements the procedures of IEEE 1815-2012 listed above in both
roles, including file transfer, the dual end point and Secure
Authentication version 5 with session key change, aggressive mode and
statistics. Against the references:

| Capability | go-dnp3 | stepfunc dnp3 | opendnp3 | DSC go-dnp3 | Triangle MicroWorks SCL |
|---|:---:|:---:|:---:|:---:|:---:|
| File transfer, outstation | ✅ | — | — | ✅ | ✅ |
| Time and interval (g50v4) from the outstation | ✅ | — | ✅ | ✅ | ✅ |
| File transfer, master | ✅ | ✅ (no delete) | — | ✅ | ✅ |
| SAv5 challenge-reply, session key change | ✅ | — | — (removed in 2016) | ✅ | ✅ |
| SAv5 aggressive mode | ✅ | — | — | — | ✅ |
| SAv5 security statistics | ✅ | — | — | ✅ | ✅ |
| SAv5 remote update key change, user management | — | — | — | — | ✅ |
| AES-GMAC | — | — | — | — | ✅ |
| Dual end point | ✅ | ✅ | ✅ | ✅ | ✅ |
| Command events (g13, g43) from the outstation | ✅ | — | — | ✅ | ✅ |
| Virtual terminal (g112, g113), data sets (g85..g88) | — codec only | not documented | not documented | ✅ outstation data set backend, terminals | ✅ |

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
