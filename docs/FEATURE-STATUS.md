# Feature status

What go-dnp3 supports, how far each part is tested, and against what.
[INTEROPERABILITY.md](../INTEROPERABILITY.md) has the detail, clause by
clause and per peer and direction; [OBJECTS.md](../OBJECTS.md) lists the
objects; what is out of scope is in [LIMITATIONS.md](../LIMITATIONS.md).

None of this is a conformance claim. Nothing is certified: only the DNP Users
Group certifies devices, and go-dnp3 declares no subset level. Peer results
show that go-dnp3 and those stacks agree with each other.

Status: go-dnp3 v1.7.0, dnp3-interop v0.11.0 (opendnp3 3.1.2, DSC go-dnp3
v0.8.2, dnp3py 0.6.0, cB-Sigma dnp3 v0.3.0, nfm-dnp3 1.0.1), dnp3c 0.2.0.

## Platforms

| Platform | Built | Tests run in CI |
|---|---|---|
| Linux amd64 | `make cross` | everything: tests with race detector, e2e, fuzz, interop, conformance |
| Linux arm64, arm | `make cross` | no |
| macOS arm64 | `make cross` | no |
| Windows amd64 | `make cross` | no |

`make cross` is run by hand, not by CI. The library packages use the standard
library only ([README.md](../README.md#install)). Serial ports are opened by
the application and handed over as a byte stream.

## Features

✅ supported · ◐ partly (see the notes) · ⚙ codec only, no procedures · — not
implemented.

**Own tests** names the tests of this repository between go-dnp3's own ends
or against scripted peers. **Independent** names the software that is not
go-dnp3 and exchanged the feature with it in `make interop`: **M** with
go-dnp3 as master, **O** with go-dnp3 as outstation. One independent peer means
the feature rests on that one implementation.

| Feature | Status | Own tests | Independent |
|---|:---:|---|---|
| TCP | ✅ | `e2e` | opendnp3, DSC go-dnp3, dnp3py, cB-Sigma dnp3, nfm-dnp3 |
| TLS, mutual authentication | ✅ | `client`, `server` | opendnp3, DSC go-dnp3: M O; cB-Sigma dnp3: M O |
| UDP | ✅ | `e2e/transport_test.go` | opendnp3, DSC go-dnp3: M O; cB-Sigma dnp3: M O |
| Serial, as a byte stream | ✅ | `e2e/transport_test.go` (`TestStream`) | opendnp3, DSC go-dnp3: M O, over a pseudo-terminal; cB-Sigma dnp3: M O |
| Dual end point, TCP | ✅ | `e2e/dualendpoint_test.go` | opendnp3, DSC go-dnp3: M O; cB-Sigma dnp3: M O |
| Dual end point, TLS | ✅ | `client`, `server` | opendnp3, DSC go-dnp3: M O; cB-Sigma dnp3: M O |
| Link layer: confirmed user data, frame count bit | ✅ | `internal/channel`, `TestLinkConfirmedMode` | DSC go-dnp3: M O |
| Link layer: keep-alive | ✅ | `internal/channel` | opendnp3: O; DSC go-dnp3: M O; cB-Sigma dnp3: M O |
| Reads, integrity and event polls, event confirmation | ✅ | `e2e/features_test.go` | opendnp3, DSC go-dnp3: M O; dnp3py: O; cB-Sigma dnp3: M O; nfm-dnp3: O, reads of ranges only |
| Event reads by count (0x07..0x09), by group across classes, in a requested variation; events kept until confirmed | ✅ | `server/eventread_test.go`, `e2e/eventread_test.go` | not yet in `make interop` |
| Confirmation only of fragments parsed whole, solicited and unsolicited | ✅ | `client/confirm_test.go` | not yet in `make interop` |
| Responses of several fragments | ✅ | `TestMultiFragmentResponse` | not a row of the [coverage matrix](../INTEROPERABILITY.md#interop-coverage) |
| Event buffer overflow | ✅ | `TestEventBufferOverflow` | opendnp3, DSC go-dnp3, dnp3py, cB-Sigma dnp3: M O; nfm-dnp3: O |
| Controls: select-before-operate, direct operate, set-points | ✅ | `e2e/features_test.go`, `server/conformance_test.go` | opendnp3, DSC go-dnp3: M O; dnp3py: O; cB-Sigma dnp3: M O |
| Several controls in one request | ✅ | `TestTooManyControls` | opendnp3, DSC go-dnp3: M O; dnp3py: O; cB-Sigma dnp3: M O |
| Unsolicited responses | ✅ | `TestUnsolicited` | opendnp3, DSC go-dnp3: M O; dnp3py: O; cB-Sigma dnp3: M O |
| Time synchronization, LAN and non-LAN | ✅ | `TestTimeSync`, `TestAutomaticTimeSync` | opendnp3, DSC go-dnp3: M O; dnp3py: O; cB-Sigma dnp3: M O; nfm-dnp3: O |
| Cold and warm restart | ✅ | `TestRestarts` | opendnp3, DSC go-dnp3: M O; dnp3py: O; cB-Sigma dnp3: M O; nfm-dnp3: O |
| Freeze and freeze-and-clear | ✅ | `TestAssignClassAndFreeze` | opendnp3, DSC go-dnp3: M O; dnp3py: O; cB-Sigma dnp3: M O; nfm-dnp3: O |
| FREEZE AT TIME, scheduled | ✅ | `server/freeze_test.go` | DSC go-dnp3: M O; dnp3py: O; cB-Sigma dnp3: M O; nfm-dnp3: O |
| Analog freeze | ✅ | `server/freeze_test.go` | opendnp3: O; DSC go-dnp3: M; dnp3py: O; cB-Sigma dnp3: O; nfm-dnp3: O |
| Frozen analog inputs (g31) | ✅ | `server/freeze_test.go` | DSC go-dnp3: M O; cB-Sigma dnp3: O; nfm-dnp3: O |
| Assign class | ✅ | `TestAssignClassAndFreeze` | opendnp3: M O; DSC go-dnp3: M; dnp3py: O; cB-Sigma dnp3: M O; nfm-dnp3: O |
| Deadbands (g34) | ✅ | `server/commandevents_test.go` | DSC go-dnp3: M O, write only; cB-Sigma dnp3: M O, write only; nfm-dnp3: O, write only |
| Device attributes | ✅ | `e2e/attributes_test.go`, `TestAttributes` | DSC go-dnp3: M O; cB-Sigma dnp3: O |
| Command events (g13, g43) | ✅ | `e2e/commandevents_test.go` | opendnp3: O; DSC go-dnp3: M O; cB-Sigma dnp3: O |
| Time and interval (g50v4) | ✅ | `server/commandevents_test.go` | opendnp3: O; DSC go-dnp3: M; cB-Sigma dnp3: O |
| Broadcast | ✅ | `client`, `server`, `internal/channel` | opendnp3: M; DSC go-dnp3: M O; cB-Sigma dnp3: M O |
| Management functions (INITIALIZE, START, STOP, SAVE) | ✅ | `server/conformance_test.go` (refusal without a handler) | opendnp3: O; DSC go-dnp3: M; cB-Sigma dnp3: O; nfm-dnp3: O |
| ACTIVATE_CONFIG with its status (g91v1) | ✅ | `e2e/activateconfig_test.go`, `TestActivateConfigResponse`, `client/activate_test.go`, `app/activation_test.go` (DSC go-dnp3's answer as a known vector) | not yet in `make interop` |
| Withheld application confirmations (`WithSolicitedConfirm`, `WithUnsolicitedConfirm`), test options | ✅ | `e2e/activateconfig_test.go` | not yet in `make interop` |
| Several outstations behind one port | ✅ | `server/group_test.go` | opendnp3, DSC go-dnp3: M O; dnp3py: O; cB-Sigma dnp3: M O; nfm-dnp3: O |
| Master for several outstations on one shared channel | — | | |
| File transfer, master | ✅ | `TestFiles`, `client/file_test.go` | DSC go-dnp3; cB-Sigma dnp3 |
| File transfer, outstation | ✅ | `TestFiles`, `server/file_test.go` | DSC go-dnp3; cB-Sigma dnp3 |
| Secure Authentication v5: challenges, session key change | ✅ | `e2e/auth_test.go` | DSC go-dnp3: M O; cB-Sigma dnp3: M O |
| Secure Authentication v5: statistics | ✅ | `TestSecurityStatistics`, `secauth/stats_test.go` | DSC go-dnp3: M O; cB-Sigma dnp3: O |
| Secure Authentication v5: aggressive mode | ◐ | `server/aggressive_test.go`, `client/keys_test.go` | none: no peer in dnp3-interop has it |
| Update key change, user management, certificates (g120v8, v10..v15) | ⚙ objects only | | none |
| AES-GMAC | — | | |
| Challenges of critical responses by the master | — | | |
| Virtual terminal (g112, g113), data sets (g85..g88) | ⚙ | | none |

## Conformance procedures

`make conformance` runs the DNP Users Group's IED certification procedures,
as dnp3c 0.2.0 implements them, against the
[test outstation](../internal/cmd/conformance): 3.1 rev 1 at subset levels 2
and 3, and 2.7 at level 2. This covers the outstation role of that test
outstation's Device Profile, not the master.
[LIMITATIONS.md](../LIMITATIONS.md#conformance-and-certification) lists what
the run leaves out.
