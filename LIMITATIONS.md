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

## Secure Authentication

- Update keys are configured out of band. The remote update key change,
  user management (g120v8, g120v10..v15, certificates) and AES-GMAC are not
  implemented.
- Aggressive mode is verified between go-dnp3's ends only: no reference
  stack in the interop suite has it.
- The master does not challenge critical responses from an outstation.
- Without an update key, `secauth.User.Key` is used as the session key with
  no session key change. This is outside SAv5, works only between go-dnp3
  ends or a peer configured the same way, and is meant for testing (see
  [SECURITY.md](SECURITY.md)).

## Objects without procedures

Data sets, private registration objects and the virtual terminal (groups 83,
85..88, 90, 91 carried raw, except the one-octet data set characteristics
g86v2; 112, 113 decoded) have no procedures: exchange them with the generic
request methods.

## Behaviour to plan for

- **UDP outstation**: one socket serves one master at a time; a master
  behind another address takes it over when it sends.
- **Multi-fragment requests** are not reassembled by the outstation: a
  request is one fragment.
- **Associations are per master address**: a master that reconnects while
  its old connection stands takes over, and the old connection is closed.
