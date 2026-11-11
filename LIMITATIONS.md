# Limitations

What go-dnp3 does not do, or does with restrictions. Details and the
comparison with other stacks are in
[INTEROPERABILITY.md](INTEROPERABILITY.md#feature-completeness-and-the-remaining-gaps).

## Conformance and certification

- **Nothing here is certified.** CI runs the DNP Users Group's IED
  certification procedures (dnp3c: 3.1 rev 1 at subset levels 2 and 3, 2.7
  at level 2) against a [test outstation](internal/cmd/conformance) built on
  the library. That run is not a certification, and go-dnp3 declares no
  subset level of its own.
- The dnp3c run does not cover what its Device Profile leaves out:
  double-bit inputs in 3.1r1 (the 2.7 run has them), serial and UDP,
  multi-drop, and the network tests of section 9.
- Peer results show that go-dnp3 and those stacks agree with each other;
  see [INTEROPERABILITY.md](INTEROPERABILITY.md) for what was run.
- **No DNP3 hardware.** No test runs against an RTU or IED, and none of the
  recorded traffic in [testdata/captures](testdata/captures/README.md)
  identifies a physical device: it is software-generated or of unknown
  origin. The secure authentication recordings cannot be checked beyond
  their decoding: their keys are not in them.
- **No subset level is declared**, and the defaults are not tied to one:
  level-dependent options (event buffers, unsolicited, controls per
  request, attributes) are the application's to set. The group 0
  attributes of level 4 are reported only when the application sets
  them (`WithAttributes`, `WithAttributeSet`).
- **No XML Device Profile ships.** The "Device Profile" of the dnp3c run
  is that runner's INI file, not the XML profile of IEEE 1815-2012.

## Secure Authentication

- Update keys are configured out of band. The remote update key change,
  user management (g120v8, g120v10..v15, certificates) and AES-GMAC are not
  implemented.
- Aggressive mode is verified between go-dnp3's ends only: no reference
  stack in the interop suite has it. Its MAC follows Table A-9 since this
  release; it does not interoperate with go-dnp3 releases before it.
- The master does not challenge critical responses from an outstation.
- Secure Authentication is off by default (IEEE 1815-2012 clause 7.6.1.4.8
  asks for on): a library cannot enable it without keys. On the outstation
  it is set per `Server` and applies to every master of that server; each
  master has its own association, with its own session keys, sequence
  numbers and statistics. One user per association.
- The outstation does not report to other associations that the maximum
  session key status count was exceeded (clause 7.6.1.4.6, error 12); it
  logs it. It does not report g0v209/g0v210 by itself; set them with
  `server.WithAttributes`.
- `client.Broadcast` does not use aggressive mode: with secure
  authentication the outstation discards a critical broadcast from a
  go-dnp3 master.
- A master with secure authentication and an update key fails `Connect`
  when the outstation does not take part in the session key change
  (clause 7.3.6 suggests carrying on with non-critical requests).
- With an update key, the master knows which requests are critical only
  from Table 7-7 (MANDATORY) and `WithAggressiveMode`: those it does not
  send while its session keys are not valid. Another function the
  outstation challenges is sent, and fails on the challenge.
- Without an update key, `secauth.User.Key` is used as the session key with
  no session key change. This is outside SAv5, works only between go-dnp3
  ends or a peer configured the same way, and is meant for testing (see
  [SECURITY.md](SECURITY.md)). Those keys never expire and are not
  invalidated after authentication failures.
- The statistics of authorization (user roles), of update key changes and
  of critical messages sent by the outstation stay 0: those procedures are
  not implemented.

## Objects without procedures

Data sets, private registration objects and the virtual terminal (groups 83,
85..88, 90 carried raw, except the one-octet data set characteristics g86v2;
112, 113 decoded) have no procedures: exchange them with the generic request
methods. Group 91 is decoded for ACTIVATE_CONFIG (`Client.ActivateConfig`,
`server.ActivateConfigHandler`). The device storage buffer fill status
(g81v1) and the device profile (g82v1, carried raw) are decoded only; the
outstation does not send them. Group 100 is not supported: IEEE 1815-2012
defines no coding for it.

## Behaviour to plan for

- **Dialers**: `client.WithDialer` covers the client's TCP and TLS
  connections, its reconnects and its own dial of the dual end point;
  `server.WithDialer` covers `DialAndServe`. A `WithStream` opener opens
  its stream itself and does not use `client.WithDialer`: `client.UDP` and
  `client.UDPFrom` dial with a `net.Dialer`; use
  `client.UDPWithDialer(d, addr)`, or a `StreamOpener` of your own, to
  supply one. `client.Accept`, `WithDualEndpoint`'s listener and the
  server's listeners and UDP sockets accept and do not dial. The client's
  dialer gets the context of `Connect` (or of the reconnect attempt), not
  a dial timeout of the library: a custom dialer sets its own, as the
  default's 10 s. `client.WithDialer(nil)` is refused with
  `dnp3.ErrInvalidOption`, as since v1.0.0; `server.WithDialer(nil)` keeps
  the default.

- **UDP outstation**: one socket serves one master at a time; a master
  behind another address takes it over when it sends. `WithMasterIPs` and
  `ServeUDPFixed` limit who may.
- **Multi-fragment requests** are not reassembled by the outstation: a
  request is one fragment.
- **Frames for another address are dropped**: a master hears only frames
  sent to its own address (`client.WithAddresses`). An outstation whose
  unsolicited responses go to a configured destination address (some
  devices default it to 0) is not heard unless that is the master's
  address; the dropped frames are logged at debug level.
- **File commands are answered at once, one block per READ**: the client
  expects the answer to every file command in the immediate response, with
  one g70v5 block in a read: OPEN_FILE, READ, WRITE, CLOSE_FILE,
  DELETE_FILE, GET_FILE_INFO, AUTHENTICATE_FILE and ABORT_FILE. IEEE
  1815-2012 4.4.17.1.2, 4.4.17.1.3 and 5.3.4 let an outstation answer with
  a null response and report the g70v4 or g70v6 object later in an event
  or unsolicited response; the client then fails the transfer with
  `dnp3.ErrProtocol`. The references in the interop suite answer at once.
- **Associations are per master address**: a master that connects again
  while its old connection stands is rejected when the old connection
  answers a link status request (13.2.3.3); a broken old connection is
  replaced. The probe takes up to the link timeout (`Link.Timeout`, 2 s by
  default, with `Link.Retries`), during which the new connection waits:
  its requests are held, and answered once it is taken.
- **The master drops broadcast frames it receives**: clauses 4 to 6 define
  broadcast only for requests to outstations.
- **The link layer's primary role is minimal**: it resets the link with
  RESET_LINK_STATES before confirmed user data only, and never sends
  TEST_LINK_STATES (Table 9-6 allows both). Collision avoidance on shared
  serial media (9.2.10) is not implemented.
- **Keep-alive can be disabled** (`Link.KeepAlive` negative) for testing;
  13.2.3.3.1 does not allow it in service.
- **Event headers with a range or index qualifier**: the outstation selects
  events by all objects (0x06) or a count (0x07..0x09). A range or an index
  list in an event header does not select points: it is answered with all
  events of the group.
- **No periodic freeze of the outstation's own**: counters are frozen on
  request (IMMED_FREEZE, FREEZE_CLEAR, FREEZE_AT_TIME with an interval). An
  application that freezes on its own schedule updates its frozen counters
  with `Database.Update` or `Database.Batch`.
- **File blocks are at most 65527 octets**: a block travels in a g70v5
  object, whose two-octet size also counts the handle and block number.
  Both ends cap the block size there, whatever the fragment size allows.
- **Files of 4 GiB or more**: the size of a file is four octets (g70v4,
  g70v7). `FSFileServer` refuses to open such a file (FILE_FATAL) and lists
  it with size 0xFFFFFFFF.
- **Output status follows the application**: a control does not change the
  binary or analog output status (g10, g40) by itself. The `Handler`
  updates the point with the value the output took, which reports its event
  (g11, g42) when the point has a class.
- **`Unsolicited.Retries` 0 means 3**: a negative value retries without
  end; there is no setting for no retries.
- **INITIALIZE_DATA reaches the `ApplicationHandler`**: the function is
  obsolete (IEEE 1815-2012 4.4.10); a handler answers it with
  `app.IINNoFuncCodeSupport`.
- **Frozen points are not checked against their running point**: a
  frozen counter or frozen analog input without the counter or analog
  input of the same index is never frozen.
- **Unsolicited reporting at startup** (`Unsolicited.Classes`) departs
  from the standard, which waits for ENABLE_UNSOLICITED; leave it empty
  for a compliant outstation.
- **DELAY_MEASURE** reports the time from the delivery of the request
  fragment.
- **Secure authentication**: a broadcast that SA discards does not set
  IIN1.0.
- **Time stamps of the time synchronization are taken at the application
  layer.** The non-LAN procedure measures the round trip from when the
  DELAY_MEASURE request is handed to the link layer to when the reassembled
  response reaches the client; IEEE 1815-2012 10.3.3.1 takes the arrival of
  the first octet, so over a slow serial line the delay includes half of
  the response's transmission time (about 12 ms for a 23-octet response at
  9600 bit/s). The LAN procedure writes the time at which the link layer
  finished writing RECORD_CURRENT_TIME (10.3.3.2); the latency of the stack
  below that is not corrected (10.3.3.2 NOTE 3).
- **Receive fragments below 2048 octets are outside the standard.**
  `client.WithMaxFragment` accepts 249 to 2047 for testing and for peers
  known to send less; 4.3 Rule 3 requires a master to receive 2048.
- **Restart and class assignment NOTEs are left to the application.** After
  `ColdRestart` or `WarmRestart` the client does not hold requests back for
  the delay the outstation returns (4.4.9 NOTE): periodic polls and the
  application's requests go on. `AssignClass` is not followed by an event
  poll of the three classes (4.4.14 NOTE).
- **ENABLE_UNSOLICITED after a restart does not wait for the null
  unsolicited response.** 5.1.1.1.2 Rule 2 step 5 enables unsolicited
  reporting once the outstation's null unsolicited response has arrived;
  the client sends ENABLE_UNSOLICITED as the last step of its restart
  procedure whether or not that response was seen, so that a lost null
  response does not leave reporting off.
