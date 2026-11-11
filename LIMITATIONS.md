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
- **File reads are answered at once, one block per READ**: `ReadFile`
  expects the answer to OPEN_FILE, READ and CLOSE_FILE in the immediate
  response, with one g70v5 block in it. A file object reported later in an
  event or unsolicited response, or a response with several blocks, fails
  the transfer. The references in the interop suite answer this way.
- **Associations are per master address**: a master that connects again
  while its old connection stands is rejected when the old connection
  answers a link status request (13.2.3.3); a broken old connection is
  replaced. The probe takes up to the link timeout (`Link.Timeout`, 2 s by
  default, with `Link.Retries`), during which the new connection waits.
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
