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
| `(*Client).Connect(ctx)` | Open the channel and run the startup sequence |
| `(*Client).Close()` | Close, stop reconnecting and the tasks; waits for the client's goroutines |
| `(*Client).State()`, `Addr()`, `Outstation()` | Accessors |

### Options

| Option | Default | Meaning |
|--------|---------|---------|
| `WithAddresses(local, remote)` | 1, 10 | Link addresses of master and outstation |
| `WithHandler(Handler)` | none | Receives the measurements of every response and unsolicited response |
| `WithStateHandler(func(State, error))` | none | Channel state changes |
| `WithLogger`, `WithMetrics` | silent | See OBSERVABILITY.md |
| `WithDialer(Dialer)` | `net.Dialer` | TCP dialer |
| `WithStream(StreamOpener)` | TCP | Any byte stream: serial, UDP (`UDP(addr)`), a pipe |
| `WithTLS(*tls.Config)` | off | TLS |
| `WithReconnect(Reconnect)` | off | Reconnect with exponential backoff (`MinDelay`, `MaxDelay`) |
| `WithRetry(Retry)` | off | Retries of idempotent requests (`Attempts`, `Backoff`, `MaxBackoff`) |
| `WithResponseTimeout(d)` | 5 s | Per response fragment |
| `WithMaxFragment(n)` | 2048 | Largest fragment reassembled |
| `WithLink(Link)` | unconfirmed | `Confirmed`, `Timeout`, `Retries`, `KeepAlive` |
| `WithStartup(Startup)` | nothing | `DisableUnsolicited`, `Integrity`, `EnableUnsolicited` on each connect |
| `WithTimeSync(TimeSync)` | none | Synchronize on NEED_TIME: `TimeSyncLAN`, `TimeSyncNonLAN` |
| `WithAutoClearRestart(bool)` | on | Clear DEVICE_RESTART when reported |
| `WithAutoIntegrity(bool)` | on | Integrity poll on restart and overflow |
| `WithAutoEventPoll(bool)` | off | Poll the classes the IIN reports events for |
| `WithPoll(Poll)` | none | A periodic READ (`Interval`, `Headers`); repeatable |
| `WithQueueLimit(n)` | 64 | Requests that may wait for their turn |
| `WithSecureAuthentication(secauth.User)` | off | Secure Authentication: session key change with an update key, challenge replies |
| `WithKeyChangeInterval(d)` | 15 min | How often the session keys are changed |

### Requests

Every request takes a `context.Context` and returns a `*Result` (the
response fragments, `IIN`, `Measurements()`, `Headers()`) where there is
one.

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
| `EnableUnsolicited(ctx, classes...)`, `DisableUnsolicited` | ENABLE_UNSOLICITED, DISABLE_UNSOLICITED |
| `AssignClass(ctx, class, headers...)` | ASSIGN_CLASS |
| `Freeze(ctx, clear, noAck, headers...)` | IMMED_FREEZE, FREEZE_CLEAR and their `_NR` forms |
| `FreezeAtTime(ctx, at, interval, headers...)` | FREEZE_AT_TIME |
| `ClearRestart(ctx)` | WRITE g80v1 index 7 |
| `ReadAttributes(ctx, variation)`, `WriteAttribute(ctx, variation, a)` | READ / WRITE g0 |
| `Write(ctx, headers...)` | WRITE |
| `Request(ctx, fc, headers...)` | Any function code |
| `ReadFile`, `WriteFile`, `ListDirectory`, `FileInfo`, `DeleteFile`, `AuthenticateFile` | The file functions (group 70) with `FileOptions` |

Commands: `Command{Index, Value, GV}`, built with `CROB(index, op, on, off)`
and `SetPoint(index, value)`; `CommandMode`: `SelectBeforeOperate`,
`DirectOperate`, `DirectOperateNoAck`.

### Measurements

`Handler` (`HandleMeasurements(ResponseInfo, []Measurement)`) and
`HandlerFunc`; `Measurement{GV, Index, Value, Event}`; `ResponseInfo{Unsolicited,
IIN, Seq, FIR, FIN}`; `Measurements(*app.Fragment)` extracts them from any
fragment.

## Package `server`

The outstation.

### Server

| Symbol | Meaning |
|--------|---------|
| `New(opts...)` | An outstation |
| `(*Server).ListenAndServe(addr)` | TCP (with `WithTLS`, TLS) on addr, `:20000` when empty |
| `(*Server).Serve(net.Listener)` | Accept on any listener |
| `(*Server).ServeConn(io.ReadWriteCloser, net.Addr)` | Serve one stream: serial, a pipe |
| `(*Server).ServeUDP(net.PacketConn)` | DNP3 over UDP; answers the address that sent last |
| `(*Server).ServeUDPTo(net.PacketConn, net.Addr)` | The same, with the master's address known from the start |
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
| `WithHandler(Handler)` | `NopHandler` | Controls, and the optional handler interfaces |
| `WithLogger`, `WithMetrics` | silent | See OBSERVABILITY.md |
| `WithTLS(*tls.Config)` | off | TLS for `ListenAndServe` |
| `WithMaxConnections(n)` | 16 | Concurrent connections |
| `WithMaxFragment(tx, rx)` | 2048, 2048 | Largest response sent, request reassembled |
| `WithConfirmTimeout(d)` | 5 s | Wait for an application confirmation |
| `WithSelectTimeout(d)` | 10 s | A SELECT's validity |
| `WithMaxControls(n)` | 16 | Controls per request; more get TOO_MANY_OBJS |
| `WithUnsolicited(Unsolicited)` | disabled | `Enabled`, `Classes`, `HoldTime`, `HoldCount`, `Retries`, `RetryDelay` |
| `WithLink(Link)` | unconfirmed | `Confirmed`, `Timeout`, `Retries`, `KeepAlive` |
| `WithEventLimits(map[PointType]int)` | 100 each | Events buffered per type and master |
| `WithTimeSync(interval)` | never | NEED_TIME at start and after the interval |
| `WithAttributes(map[uint8]app.Attribute)` | none | Device attributes of set 0 |
| `WithFileServer(FileServer)` | none | File transfer |
| `WithSecureAuthentication(SecureAuth)` | off | Challenge critical requests (`User`, `Critical`, default `DefaultCritical`) |

### Database

| Symbol | Meaning |
|--------|---------|
| `PointType` | `BinaryInput`, `DoubleBitInput`, `BinaryOutput`, `Counter`, `FrozenCounter`, `AnalogInput`, `FrozenAnalogInput`, `AnalogOutput`, `OctetString` |
| `PointConfig` | `Class`, `StaticVariation`, `EventVariation`, `Deadband`, `ExcludeFromClass0` |
| `(*Database).Add`, `Remove`, `Get`, `Len` | Points |
| `(*Database).Update(t, index, value, mode)` | `EventOnChange`, `EventForce`, `EventSuppress` |
| `(*Database).Batch(func(*Batch) error)` | Updates whose events are reported together |
| `AddBinaryInput` ... `AddOctetString`, `UpdateBinaryInput` ... `UpdateOctetString` | Typed forms |

### Handlers

| Interface | Called for |
|-----------|-----------|
| `Handler` | `Select(ctx, Command)`, `Operate(ctx, Command, OperateType)` return the status |
| `RestartHandler` | COLD_RESTART, WARM_RESTART |
| `TimeHandler` | Every time synchronization |
| `ApplicationHandler` | INITIALIZE_DATA, the application functions, SAVE_CONFIG, ACTIVATE_CONFIG |
| `WriteHandler` | WRITE of device attributes and octet strings |

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
| `Fragment{Control, Function, IIN, Headers}` | `Encode`, `AppendEncode`, `String`; `Decode(b)` |
| `Header{GV, Qualifier, Start, Stop, Count, Objects}` | `EncodedLen`, `String` |
| `Object{Index, Value}`, `Value` | The closed set of value types |
| `GroupVariation`, `GV(g, v)`, `G1V2` ... `G122V2` | `Group`, `Variation`, `Name`, `Known`, `IsEvent`, `Size` |
| `FunctionCode`, `Func*` | `String`, `Defined`, `IsResponse`, `NoAck` |
| `IIN`, `IIN*` | `Has`, `IIN1`, `IIN2`, `String`; `IINBit` |
| `Control`, `SingleControl`, `ParseControl`, `NextSeq` | The application control octet |
| `Qualifier`, `Qual*`, `RangeQualifier`, `CountQualifier`, `IndexQualifier` | Qualifier codes |
| `AllObjects`, `ClassHeaders`, `IndexRange`, `IndexList`, `CountOf`, `Ranged`, `Indexed`, `Counted`, `FreeFormat` | Header constructors |
| `Timestamp`, `TimestampOf`, `Now` | DNP3 time |
| Point values | `Binary`, `DoubleBitBinary`, `BinaryCommandEvent`, `CROB`, `Counter`, `Analog`, `AnalogDeadband`, `AnalogOutput`, `AnalogCommandEvent`, `AbsoluteTime`, `CTO`, `TimeDelay`, `OctetString`, `BCD`, `UnsignedInteger`, `SecurityStatistic`, `Raw` |
| Enumerations | `Flags`, `DoubleBit`, `CommandStatus`, `OpType`, `TripClose`, `IntervalUnit` |
| Attributes | `Attribute`, `AttrType`, `Attr*` variations, `StringAttribute`, `UintAttribute`, `IntAttribute`, `FloatAttribute`, `TimeAttribute`, `ListAttribute`, `AttributeListEntry` |
| Files | `FileAuthentication`, `FileCommand`, `FileCommandStatus`, `FileTransport`, `FileTransportStatus`, `FileDescriptor`, `FileSpecification`, `FileMode`, `FileStatus`, `FileType`, `Permissions`, `AppendFileDescriptor`, `DecodeFileDescriptors` |
| Authentication | `AuthChallenge` ... `AuthUpdateKeyChangeConfirmation`, `MACAlgorithm`, `KeyWrap`, `KeyStatus`, `AuthErrorCode`, `ChallengeReason` |
| Errors | `ErrMalformed`, `ErrUnknownObject`, `ErrInvalidQualifier`, `ErrInvalidValue`, `ErrUnknownFunction` |

## Package `transport`

`Header` (`NewHeader`, `FIR`, `FIN`, `Seq`), `Segmenter` (`Segment`,
`Seq`), `Reassembler` (`NewReassembler`, `Add`, `Reset`, `Pending`),
`MaxSegmentData`, `DefaultMaxFragment`; errors `ErrEmpty`, `ErrNoFirst`,
`ErrSequence`, `ErrTooLarge`.

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

`app.AppendObjectValue(b, gv, v)` encodes one object without header, as a
free-format object carries it.
