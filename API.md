# API Reference: otfabric/go-dnp3

The public API by package. The [Go reference](https://pkg.go.dev/github.com/otfabric/go-dnp3)
has every symbol with its documentation; this page is the map.

## Table of contents

- [Package `dnp3`](#package-dnp3)
- [Package `client`](#package-client)
- [Package `server`](#package-server)
- [Package `app`](#package-app)
- [Package `transport`](#package-transport)
- [Package `link`](#package-link)
- [Package `secauth`](#package-secauth)

## Package `dnp3`

What client and server share.

### Errors

| Symbol | Kind | Meaning |
|--------|------|---------|
| `ErrClosed` | sentinel | Operation on a closed client, server or association |
| `ErrNotConnected` | sentinel | Request on a client without a channel |
| `ErrConnectFailed` | sentinel | Dial, TLS handshake or stream opener failed |
| `ErrConnectionLost` | sentinel | The channel ended during a request |
| `ErrTimeout` | sentinel | No response, confirmation or link answer in time |
| `ErrProtocol` | sentinel | The peer violated the protocol |
| `ErrBusy` | sentinel | Already connected, or too many requests waiting |
| `ErrInvalidOption` | sentinel | An option or argument a client or server cannot use |
| `ErrAuthentication` | sentinel | Secure authentication failed |
| `*IINError` | type | The outstation refused a request: `Function`, `IIN` |
| `IINErrorBits` | const | The IIN2 bits that make a response an `IINError` |
| `*CommandError` | type | A control was not executed: `GV`, `Index`, `Status` |
| `*FileError` | type | A file operation was refused: `Op`, `Status`, `Text` |
| `*AuthError` | type | An authentication error from the peer: `Code`, `User`, `Text`; matches `ErrAuthentication` |

See [ERRORS.md](ERRORS.md).

### State

`State`: `StateDisconnected`, `StateConnecting`, `StateConnected`.

### Logger and Metrics

| Symbol | Meaning |
|--------|---------|
| `Logger` | `Debugf`, `Infof`, `Warnf`, `Errorf` |
| `FieldLogger` | `Logger` with key-value entries and `With` |
| `ContextLogger` | `Logger` with context-aware entries |
| `NopLogger()`, `NewStdLogger(*log.Logger)`, `NewSlogLogger(slog.Handler)`, `NewSlogFieldLogger(slog.Handler)` | Constructors |
| `Metrics` | Connections, frames, framing errors, fragments, decode errors |
| `NopMetrics` | Embed to implement only some callbacks |
| `RequestMetrics` | Client: `OnRequest`, `OnRequestDone`, `OnRetry` |
| `ServerMetrics` | Server: `OnHandled`, `OnEventsDiscarded`, `OnUnsolicited` |

See [OBSERVABILITY.md](OBSERVABILITY.md).

## Package `client`

The master for one outstation.

### Construction and lifecycle

| Symbol | Meaning |
|--------|---------|
| `New(addr, opts...)` | A client; not connected yet. The port defaults to 20000 |
| `Dial(ctx, addr, opts...)` | `New` and `Connect` |
| `(*Client).Connect(ctx)` | Open the channel and run the startup sequence; when the sequence fails, the channel is closed and the client is disconnected |
| `(*Client).Close()` | Close, stop reconnecting and the tasks; waits for the client's goroutines |
| `(*Client).State()`, `Addr()`, `Outstation()` | Accessors |
| `(*Client).SecurityStatistics()` | The master's security statistics, indexed by `secauth.Statistic` (session key changes, challenges answered, errors received, ...); all zero without secure authentication |

### Options

| Option | Default | Meaning |
|--------|---------|---------|
| `WithAddresses(local, remote)` | 1, 10 | Link addresses of master and outstation |
| `WithHandler(Handler)` | none | Receives the measurements of every response and unsolicited response |
| `WithStateHandler(func(State, error))` | none | Channel state changes |
| `WithLogger`, `WithMetrics` | silent | See [OBSERVABILITY.md](OBSERVABILITY.md) |
| `WithDialer(Dialer)` | `net.Dialer` with a 10 s timeout | TCP dialer; the TLS handshake that follows is bounded to 10 s |
| `WithStream(StreamOpener)` | TCP | Any byte stream: serial, UDP (`UDP(addr)`, or `UDPFrom(local, remote)` from a fixed local port), an outstation that connects (`Accept(net.Listener)`, listening only), a pipe |
| `WithDualEndpoint(net.Listener, allow)` | off | The TCP dual end point (13.2.3.1.3): dial the outstation and take the connections it establishes on the listener, one at a time, the master's own first; `allow` validates the outstation's address. `Close` closes the listener; excludes `WithStream` |
| `WithTLS(*tls.Config)` | off | TLS |
| `WithReconnect(Reconnect)` | off | Reconnect with exponential backoff (`MinDelay`, `MaxDelay`) |
| `WithRetry(Retry)` | off | Retries of idempotent requests (`Attempts`, `Backoff`, `MaxBackoff`) |
| `WithResponseTimeout(d)` | 5 s | Per response fragment |
| `WithMaxFragment(n)` | 2048 | Largest fragment reassembled |
| `WithLink(Link)` | unconfirmed | `Confirmed` (serial only: 13.2.1.1 forbids it over IP), `Timeout` (2 s), `Retries`, `KeepAlive` (60 s, any positive duration; negative disables it, for testing only) |
| `WithStartup(Startup)` | nothing | `DisableUnsolicited`, `Integrity`, `EnableUnsolicited` on each connect |
| `WithTimeSync(TimeSync)` | `TimeSyncNone` | Synchronize on NEED_TIME: `TimeSyncLAN`, `TimeSyncNonLAN` |
| `WithAutoClearRestart(bool)` | on | Clear DEVICE_RESTART when reported |
| `WithAutoIntegrity(bool)` | on | Integrity poll on restart and overflow |
| `WithAutoEventPoll(bool)` | off | Poll the classes the IIN reports events for |
| `WithSolicitedConfirm(bool)` | on | Confirm solicited responses that ask for it. Off is for tests and diagnostics only: the outstation keeps the events it sent, and a multi-fragment response stalls after its first fragment |
| `WithUnsolicitedConfirm(bool)` | on | Confirm unsolicited responses that ask for it. Off is for tests and diagnostics only: the outstation repeats them; a repeat reaches the `Handler` once |
| `WithPoll(Poll)` | none | A periodic READ (`Interval`, `Headers`); repeatable |
| `WithQueueLimit(n)` | 64 | Requests that may wait for their turn |
| `WithSecureAuthentication(secauth.User)` | off | Secure Authentication: session key change with an update key (on connect, at the interval, after the key change count, after an outstation restart, and again soon after an authentication failure, at most 3 times until a change succeeds; while there are no keys a backoff from 1 s, at most 3 retries, then the interval), challenge replies, the key status authenticated with the last monitoring key |
| `WithKeyChangeInterval(d)` | 15 min | How often the session keys are changed; 0 turns the interval off, leaving the count |
| `WithKeyChangeCount(n)` | 1000 (`DefaultKeyChangeCount`) | The session keys are also changed after n authentication messages sent or received; 1..`MaxKeyChangeCount` (2^31) |
| `WithChallengeMACs(algs...)` | all but HMAC-SHA-1/4, and over TCP/UDP the 8-octet truncations | The MAC algorithms an outstation's challenge may ask for; the reply and the aggressive mode requests use the challenge's algorithm |
| `WithAggressiveMode(fcs...)` | off | Send these function codes (`secauth.DefaultCritical` when none) in aggressive mode, once a challenge was answered since the last key change; a refused request makes the next one challenged, error 4 turns it off for the connection; `New` refuses it without `WithSecureAuthentication` |

Constants: `DefaultPort` (20000), the port `Dial` uses when the address has none;
`DefaultKeyChangeCount` (1000) and `MaxKeyChangeCount` (2^31), the default and
the largest session key change count.

### Requests

Every request takes a `context.Context` and returns a `*Result` (its fields
`Fragments` and `IIN`, the IIN of all fragments; `Measurements()`,
`Headers()`) where there is one.

| Method | Function codes |
|--------|----------------|
| `Read(ctx, headers...)` | READ |
| `IntegrityPoll(ctx)` | READ class 1, 2, 3, 0 |
| `EventPoll(ctx, classes...)` | READ class 1..3 |
| `Operate(ctx, mode, cmds...)` | SELECT + OPERATE, DIRECT_OPERATE, DIRECT_OPERATE_NR; returns the statuses |
| `WriteTime(ctx, t)` | WRITE g50v1 |
| `SyncTime(ctx, procedure)` | RECORD_CURRENT_TIME + WRITE g50v3, or DELAY_MEASURE + WRITE g50v1 |
| `DelayMeasure(ctx)` | DELAY_MEASURE |
| `ColdRestart(ctx)`, `WarmRestart(ctx)` | COLD_RESTART, WARM_RESTART; return the delay |
| `ActivateConfig(ctx, headers...)` | ACTIVATE_CONFIG with file specifications (g70v8) or octet strings (g110); returns the `app.ActivateConfigStatus` of each g91v1 object of the response, `ErrProtocol` without one; never retried |
| `EnableUnsolicited(ctx, classes...)`, `DisableUnsolicited` | ENABLE_UNSOLICITED, DISABLE_UNSOLICITED |
| `AssignClass(ctx, class, headers...)` | ASSIGN_CLASS |
| `Freeze(ctx, clear, noAck, headers...)` | IMMED_FREEZE, FREEZE_CLEAR and their `_NR` forms |
| `FreezeAtTime(ctx, at, interval, headers...)` | FREEZE_AT_TIME; an interval below 0 or of 2^32 ms or more is an `ErrInvalidOption` |
| `ClearRestart(ctx)` | WRITE g80v1 index 7 |
| `ReadAttributes(ctx, variation)`, `WriteAttribute(ctx, variation, a)` | READ / WRITE g0, set 0 |
| `ReadAttributeSet(ctx, set, variation)`, `WriteAttributeSet(ctx, set, variation, a)` | The same for another set |
| `Write(ctx, headers...)` | WRITE |
| `Request(ctx, fc, headers...)` | Any function code |
| `ReadFile`, `WriteFile`, `ListDirectory`, `FileInfo`, `DeleteFile`, `AuthenticateFile` | The file functions (group 70); `ReadFile`, `WriteFile`, `ListDirectory` and `DeleteFile` take `FileOptions` (`MaxBlockSize`, `AuthKey`, `Permissions`, `Append`) |
| `Broadcast(ctx, dest, fc, headers...)` | A request to a broadcast address (`link.BroadcastNoConfirm` 0xFFFD, `BroadcastConfirm` 0xFFFE, `BroadcastOptionalConfirm` 0xFFFF); no answer, IIN1.0 in the next response |

Commands: `Command{Index, Value, GV}`, built with `CROB(index, op, on, off)`
and `SetPoint(index, value)`; `CommandMode`: `SelectBeforeOperate`,
`DirectOperate`, `DirectOperateNoAck`.

### Measurements

`Handler` (`HandleMeasurements(ResponseInfo, []Measurement)`) and
`HandlerFunc`; `Measurement{GV, Index, Value, Event}`; `ResponseInfo{Unsolicited,
IIN, Seq, FIR, FIN}`; `Measurements(*app.Fragment)` extracts them from any
fragment. A measurement is indexed point data; its `Value` is one of
`app.Binary`, `DoubleBitBinary`, `BinaryCommandEvent`, `Counter`, `Analog`,
`AnalogDeadband`, `AnalogCommandEvent`, `AbsoluteTime` (g50v4), `BCD`
(g101), `UnsignedInteger` (g102), `OctetString` or `SecurityStatistic`.
[OBJECTS.md](OBJECTS.md) lists the objects.

## Package `server`

The outstation.

### Server

| Symbol | Meaning |
|--------|---------|
| `New(opts...)` | An outstation |
| `(*Server).ListenAndServe(addr)` | TCP (with `WithTLS`, TLS) on addr; when empty `:20000`, or `:19999` with TLS |
| `(*Server).Serve(net.Listener)` | Accept on any listener |
| `(*Server).ServeConn(io.ReadWriteCloser, net.Addr)` | Serve one stream: serial, a pipe |
| `(*Server).ServeUDP(net.PacketConn)` | DNP3 over UDP; answers the address that sent last |
| `(*Server).ServeUDPTo(net.PacketConn, net.Addr)` | The same, with the master's address known from the start |
| `(*Server).ServeUDPFixed(net.PacketConn, net.Addr)` | DNP3 over UDP answering one fixed master port (Table 13-1 case 1); datagrams from other IP addresses are ignored |
| `ServeByMasterIP(net.Listener, routes...)` | Multiple masters, method 1 (13.2.3.5.1): each connection goes to the first `Route{Masters, Server or Group}` whose prefix holds the master's IP address; others are closed |
| `NewGroup(servers...)` | Several outstations, each a `Server` at its own address, on the same connections (multi-drop); `(*Group).ListenAndServe`, `Serve`, `ServeConn`, `ServeUDP`, `Servers`, `Close` |
| `(*Server).DialAndServe(ctx, addr, Redial)` | The dual end point: connect to the master, serve, reconnect (`Redial{MinDelay, MaxDelay}`, 1 s and 1 min); `ctx.Err()` when ctx ends, `nil` after `Close` |
| `(*Server).Address()` | The outstation's link address |
| `(*Server).Database()` | The points |
| `(*Server).SetIndications(bits, on)` | LOCAL_CONTROL, DEVICE_TROUBLE, CONFIG_CORRUPT |
| `(*Server).Restart()` | Behave as after a restart |
| `(*Server).Now()` | The outstation's clock, set by time synchronization |
| `(*Server).CloseConnections()` | Drop the connections, keep serving |
| `(*Server).Close()` | Stop everything; waits for the goroutines |

### Options

| Option | Default | Meaning |
|--------|---------|---------|
| `WithAddress(a)` | 10 | Outstation link address |
| `WithMasters(addrs...)` | any | Masters answered; their associations exist from the start |
| `WithSelfAddress(bool)` | off | Accept the self address 0xFFFC |
| `WithMasterIPs(prefixes...)` | any | Masters by IP address: other TCP connections are closed at accept, other UDP datagrams ignored |
| `WithHandler(Handler)` | `NopHandler` | Controls, and the optional handler interfaces |
| `WithLogger`, `WithMetrics` | silent | See [OBSERVABILITY.md](OBSERVABILITY.md) |
| `WithTLS(*tls.Config)` | off | TLS for `ListenAndServe`, and the TLS client configuration of `DialAndServe` |
| `WithMaxConnections(n)` | 16 | Concurrent connections |
| `WithMaxFragment(tx, rx)` | 2048, 2048 | Largest response sent, request reassembled |
| `WithConfirmTimeout(d)` | 5 s | Wait for an application confirmation |
| `WithSelectTimeout(d)` | 10 s | A SELECT's validity |
| `WithMaxControls(n)` | 16 | Controls per request; more get TOO_MANY_OBJS |
| `WithUnsolicited(Unsolicited)` | disabled | `Enabled`, `Classes`, `HoldTime`, `HoldCount`, `Retries`, `RetryDelay` |
| `WithLink(Link)` | unconfirmed | As for the client. A TCP connection on which no master sends a frame within `KeepAlive` and `Timeout` is closed |
| `WithEventLimits(map[PointType]int)` | 100 each | Events buffered per type and master |
| `WithTimeSync(interval)` | never | NEED_TIME at start and after the interval |
| `WithDeadbandIntegerOnly(bool)` | off | Analog input deadbands (g34) in variations 1 and 2 only; a READ of g34v3 gets IIN2.1 |
| `WithAttributes(map[uint8]app.Attribute)` | none | Device attributes of set 0 |
| `WithAttributeSet(set, attrs, writable...)` | none | Device attributes of another set; the writable variations take a value of the same type |
| `WithFileServer(FileServer)` | none | File transfer |
| `WithFileTimeout(d, class)` | 5 min, class 1 | An open file no request names for `d` is closed and reported with a g70v6 HANDLE_EXPIRED event in `class` |
| `WithSecureAuthentication(SecureAuth)` | off | Challenge critical requests, accept aggressive mode, keep the security statistics: `User`, `Critical` (default `DefaultCritical`, the same as `secauth.DefaultCritical`; always completed with `secauth.MandatoryCritical`), `ReplyTimeout` (default `DefaultReplyTimeout`, 2 s), `StatisticsClass` (default 1), `StatisticsThreshold` (all statistics; unset: the defaults of Table 7-6), `Thresholds` (per statistic, 1..65 535), `NoAggressiveMode`, `ExpectedKeyChangeInterval` (default 30 min, negative: off), `ExpectedKeyChangeCount` (default 2000), `MaxKeyStatusRequests` (default 5, 2..255) |

Constants: `DefaultPort` (20000), `DefaultTLSPort` (19999), `DefaultEventLimit` (100),
`DefaultFileTimeout` (5 min), `DefaultReplyTimeout` (2 s), `DefaultExpectedKeyChangeInterval` (30 min),
`DefaultExpectedKeyChangeCount` (2000), `DefaultMaxKeyStatusRequests` (5), `MaxScheduledFreezes` (16: the FREEZE_AT_TIME
requests the server keeps waiting at once; a periodic one keeps its place
until `Close`); the variable `DefaultCritical`. `Class` is an event class
(1..3) as `PointConfig`, `Unsolicited` and `SecureAuth` take it.

### Database

| Symbol | Meaning |
|--------|---------|
| `PointType` | `BinaryInput`, `DoubleBitInput`, `BinaryOutput`, `Counter`, `FrozenCounter`, `AnalogInput`, `FrozenAnalogInput`, `AnalogOutput`, `OctetString`, `TimeAndInterval` (g50v4, no class); and, kept by the outstation and refused by `Add`, `SecurityStatistic` (per master, with secure authentication), `BinaryOutputCommand`, `AnalogOutputCommand` (command events) |
| `PointConfig` | `Class`, `StaticVariation`, `EventVariation`, `Deadband` (a finite number ≥ 0), `ExcludeFromClass0`; for outputs `CommandEventClass`, `CommandEventVariation` (g13v2, g43v3) |
| `(*Database).Add`, `Remove`, `Get`, `Len` | Points |
| `(*Database).Update(t, index, value, mode)` | `EventMode`: `EventOnChange`, `EventForce`, `EventSuppress` |
| `(*Database).Batch(func(*Batch) error)` | Updates whose events are reported together (`Batch.Update` and the typed forms) |
| `AddBinaryInput` ... `AddOctetString`, `UpdateBinaryInput` ... `UpdateOctetString` | Typed forms |

### Handlers

| Interface | Called for |
|-----------|-----------|
| `Handler` | `Select(ctx, Command)`, `Operate(ctx, Command, OperateType)` return the status |
| `RestartHandler` | COLD_RESTART, WARM_RESTART |
| `TimeHandler` | Every time synchronization |
| `ApplicationHandler` | INITIALIZE_DATA, the application functions, SAVE_CONFIG, ACTIVATE_CONFIG; returns IIN2 bits only |
| `ActivateConfigHandler` | ACTIVATE_CONFIG, instead of `ApplicationHandler`: `ActivateConfig(ctx, headers)` returns an `app.ActivateConfigStatus` and IIN2 bits; without an error bit the response carries the status in one g91v1 object, qualifier 0x07 |
| `WriteHandler` | WRITE of device attributes of set 0 and octet strings |
| `AttributeSetWriteHandler` | WRITE of a writable attribute of a `WithAttributeSet` set, before it is stored |

`NopHandler`, `HandlerFunc`; `Command{GV, Index, Value, Master}`;
`OperateType`: `SelectBeforeOperate`, `DirectOperate`, `DirectOperateNoAck`.

### File server

`FileServer` (`Open`, `Delete`, `Info`), `FileAuthenticator`, `File`
(`io.Reader`, `io.Writer`, `Size`, `Close(abort)`), `FileRequest`, and
`FSFileServer{FS}`: a read-only server over any `fs.FS` that also lists
directories.

## Package `app`

| Symbol | Meaning |
|--------|---------|
| `Fragment{Control, Function, IIN, Headers}` | `Encode`, `AppendEncode`, `HeaderLen`, `String`; `Decode(b)`; `AppendObjectValue(b, gv, v)` encodes one object without header, as a free-format object carries it; a response refuses qualifier 0x06, group 60 and request-only variations (Table 4-8) |
| `Header{GV, Qualifier, Start, Stop, Count, Objects}` | `EncodedLen`, `String` |
| `Object{Index, Value}`, `Value` | The closed set of value types |
| `GroupVariation`, `GV(g, v)`, `G1V0` ... `G122V2`, `OctetStringGV(g, n)` (variation 0 for n outside 1..255) | `Group`, `Variation`, `Name`, `Known`, `IsEvent`, `Size`; [OBJECTS.md](OBJECTS.md) lists them all |
| `FunctionCode`, `Func*` | `String`, `Defined`, `IsResponse`, `NoAck` |
| `IIN`, `IIN*` | `Has`, `IIN1`, `IIN2`, `String`; `IINBit` |
| `Control{FIR, FIN, CON, UNS, Seq}`, `SingleControl`, `ParseControl`, `NextSeq` | The application control octet (`Byte`, `String`) |
| `Qualifier`, `Qual*`, `RangeQualifier`, `CountQualifier`, `IndexQualifier` | Qualifier codes (`IsRange`, `IsCount`, `IsIndexed`, `IsFreeFormat`, `Prefix`, `Range`, `Valid`); `IndexQualifier` picks 0x17 or 0x28 while the count and indexes fit, else 0x29, 0x37, 0x38 or 0x39 (Table 4-7, 4.2.2.7.3.4) |
| `AllObjects`, `ClassHeaders`, `IndexRange`, `IndexList`, `CountOf`, `Ranged`, `Indexed`, `Counted`, `FreeFormat` | Header constructors |
| `Timestamp`, `TimestampOf`, `Now`, `MaxTimestamp` | DNP3 time (`Time`, `String`) |
| Point values | `Binary`, `DoubleBitBinary`, `BinaryCommandEvent`, `CROB`, `Counter`, `Analog`, `AnalogDeadband`, `AnalogOutput`, `AnalogCommandEvent`, `AbsoluteTime`, `CTO`, `TimeDelay`, `OctetString`, `BCD` (`Value`, `Negative`), `UnsignedInteger`, `DataSetCharacteristics` (g86v2, `Flags DataSetFlags`), `BufferFillStatus` (g81v1, `Fill`, `Overflow`, `Buffer`), `SecurityStatistic`, `Raw` |
| Enumerations | `Flags`, `DoubleBit`, `CommandStatus`, `OpType`, `TripClose`, `IntervalUnit`, `DataSetFlags` (`DataSetReadable` ... `DataSetMasterDefined`) |
| Attributes | `Attribute`, `AttrType`, `Attr*` variations, `StringAttribute`, `UintAttribute`, `IntAttribute`, `FloatAttribute`, `TimeAttribute`, `ListAttribute`, `AttributeListEntry`; read with `Text`, `Uint`, `Int`, `Float`, `List` |
| Activation status (g91v1) | `ActivateConfigStatus{Delay, Results}`, `ActivateConfigResult{Code, Text}`; `ParseActivateConfigStatus(data)` reads the data of the `Raw` that `Decode` returns for g91v1, `ActivateConfigStatus.Raw()` makes one. g91v1 decodes with a count, range or free-format qualifier |
| Files | `FileAuthentication`, `FileCommand`, `FileCommandStatus`, `FileTransport`, `FileTransportStatus`, `FileDescriptor`, `FileSpecification`, `FileMode`, `FileStatus`, `FileType`, `Permissions`, `AppendFileDescriptor`, `DecodeFileDescriptors` |
| Authentication | `AuthChallenge` ... `AuthUpdateKeyChangeConfirmation`, `MACAlgorithm`, `KeyWrap`, `KeyStatus`, `AuthErrorCode`, `ChallengeReason` |
| Errors | `ErrMalformed`, `ErrUnknownObject`, `ErrInvalidQualifier`, `ErrInvalidValue`, `ErrUnknownFunction` |

## Package `transport`

`Header` (`NewHeader`, `FIR`, `FIN`, `Seq`), `Segmenter` (`Segment`,
`Seq`), `Reassembler` (`NewReassembler`, `Add`, `Reset`, `Pending`),
`MaxSegment`, `MaxSegmentData`, `DefaultMaxFragment`; errors `ErrEmpty`, `ErrNoFirst`,
`ErrSequence`, `ErrTooLarge`, `ErrDuplicate`, `ErrNoData`.

## Package `link`

`Frame` (`Encode`, `AppendEncode`, `Control`, `Validate`, `String`),
`Decode`, `FrameLength`, `EncodedLen`, `CRC`, `Reader` (`NewReader`,
`ReadFrame`), `Function` (the `Primary*` and `Secondary*` codes), `Address`
(`BroadcastConfirm`, `BroadcastNoConfirm`, `BroadcastOptionalConfirm`,
`SelfAddress`, `MaxStationAddress`); errors `ErrFraming` (wrapped by all),
`ErrInvalidStart`, `ErrInvalidLength`, `ErrCRC`, `ErrInvalidFunction`,
`ErrShortBuffer`.

## Package `secauth`

`MAC(alg, key, data)`, `Equal(a, b)`, `AuthData(challenge, critical)`,
`KeyWrap(kek, plaintext)`, `KeyUnwrap(kek, wrapped)` (RFC 3394, `ErrKeyWrap`),
`KeyChangeData(control, monitoring, keyStatus)`, `ParseKeyChangeData(plain, keyStatus...)`,
`User{Number, UpdateKey, Key, MAC}` (`Algorithm`, `KeyWrapAlgorithm`, `SessionKeyLen`, `Validate`).
`Statistic` (`StatUnexpectedMessages` ... `StatRekeysDueToRestarts`, `NumStatistics`, `String`,
`DefaultThreshold`): the security statistics as g121 indexes, with the default event thresholds
of Table 7-6. `DefaultCritical`: the function codes challenged by default and sent in aggressive
mode. `MandatoryCritical`: the codes Table 7-7 marks MANDATORY, which package server always
challenges. `AggressiveOverhead`: what aggressive mode adds to a request.

