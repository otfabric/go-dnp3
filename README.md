# go-dnp3 - DNP3 (IEEE 1815) Master and Outstation Library for Go

[![Go Version](https://img.shields.io/badge/Go-1.23%2B-00ADD8?style=flat&logo=go)](https://go.dev/)
[![Go Reference](https://pkg.go.dev/badge/github.com/otfabric/go-dnp3.svg)](https://pkg.go.dev/github.com/otfabric/go-dnp3)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI Status](https://github.com/otfabric/go-dnp3/actions/workflows/ci.yml/badge.svg)](https://github.com/otfabric/go-dnp3/actions/workflows/ci.yml)
[![Interop](https://github.com/otfabric/go-dnp3/actions/workflows/interop.yml/badge.svg)](https://github.com/otfabric/go-dnp3/actions/workflows/interop.yml)
[![Code Coverage](https://codecov.io/gh/otfabric/go-dnp3/graph/badge.svg)](https://codecov.io/gh/otfabric/go-dnp3)

A pure Go implementation of DNP3 (IEEE 1815-2012), the SCADA protocol
between masters and outstations in electric, water and oil and gas
utilities. No cgo, no dependencies outside the standard library.

The library provides:

- A **client** (master): integrity and event polls, reads of any group and
  range, unsolicited responses with confirmation and duplicate detection,
  controls (select-before-operate, direct operate, no-ack; relay output
  blocks, pattern control, set-points), time synchronization by the LAN and
  the non-LAN procedure, restarts, freezes (also at a time), assign class,
  device attributes of any set, file transfer, broadcasts, secure
  authentication
- A **server** (outstation): a point database for every point type with
  deadbands and event classes, event buffers per master that survive
  reconnects, multi-fragment responses with confirmation, unsolicited
  responses with hold time and retries, select-before-operate with timeout
  and sequence checks, device attributes of any set, scheduled freezes,
  any number of masters and connections
- The complete **link layer** (FT3 frames, CRCs, reset of link states,
  confirmed user data with the frame count bit, link status keep-alive) and
  the **transport function**, also on multi-drop channels
- An **application layer codec** and object library for every group of
  IEEE 1815-2012 Annex A in use today: file control (g70), device
  attributes (g0) and the secure authentication objects (g120..g122)
  included
- **Secure Authentication v5** (IEEE 1815-2012 clause 7): the session key
  change with AES key wrap under a pre-shared update key, on every
  connection, at an interval and after an authentication failure; the
  outstation challenges critical requests, the master answers with an
  HMAC or sends them in aggressive mode; the outstation keeps the
  security statistics (g121, g122)
- What production use needs: `context.Context` on every call, automatic
  reconnect with backoff, retries for the requests that are safe to repeat,
  automatic handling of the internal indications (restart, time, events,
  overflow), periodic polls, structured logging, metrics hooks, TCP, TLS,
  UDP and serial (any byte stream)
- **Verified against third-party stacks**: as master and as outstation
  against Step Function I/O's dnp3, opendnp3, DSC go-dnp3 and
  dnp3py, in the containers of
  [otfabric/dnp3-interop](https://github.com/otfabric/dnp3-interop) v0.4.1,
  over TCP, TLS, UDP and serial, with file transfer and Secure
  Authentication

**Docs:** [API.md](API.md) (public API) · [ARCHITECTURE.md](ARCHITECTURE.md) (packages, goroutines, protocol machines) · [INTEROPERABILITY.md](INTEROPERABILITY.md) (what is implemented, clause by clause) · [ERRORS.md](ERRORS.md) (error semantics) · [OBSERVABILITY.md](OBSERVABILITY.md) (logging and metrics) · [SECURITY.md](SECURITY.md) · [RELEASE.md](RELEASE.md) (changelog)

## Table of contents

- [go-dnp3 vs stepfunc dnp3, opendnp3 and DSC go-dnp3](#go-dnp3-vs-stepfunc-dnp3-opendnp3-and-dsc-go-dnp3)
- [Install](#install)
- [Project structure](#project-structure)
- [Client quickstart](#client-quickstart)
- [Server quickstart](#server-quickstart)
- [Production features](#production-features)
- [Transports](#transports)
- [The object model](#the-object-model)
- [Error semantics](#error-semantics)
- [Examples](#examples)
- [Development](#development)
- [Interop tests](#interop-tests)
- [Limitations](#limitations)
- [License](#license)

## go-dnp3 vs stepfunc dnp3, opendnp3 and DSC go-dnp3

go-dnp3 is tested against four other implementations, three of which this table compares (see
[Interop tests](#interop-tests)). All are good libraries; this table shows
where they differ so you can pick the right one for your project.

| Capability | otfabric/go-dnp3 | stepfunc dnp3 | opendnp3 | DSC go-dnp3 |
|---|:---:|:---:|:---:|:---:|
| Language | Go | Rust (C, C++, .NET, Java bindings) | C++ (Java, .NET bindings) | Go |
| License | MIT | non-commercial; commercial licence available | Apache-2.0 | GPL-3.0 |
| Maintained | ✅ | ✅ | — archived 2022 | ✅ young (v0.8) |
| Master and outstation | ✅ | ✅ | ✅ | ✅ |
| Unsolicited responses, both roles | ✅ | ✅ | ✅ | ✅ |
| Select-before-operate, direct operate | ✅ | ✅ | ✅ | ✅ |
| Direct operate no-ack, as master | ✅ | — ¹ | — ¹ | ✅ |
| LAN and non-LAN time synchronization | ✅ | ✅ | ✅ | ✅ |
| Assign class, as outstation | ✅ | — ¹ | ✅ | ✅ |
| File transfer (g70) | ✅ both roles | master | — | ✅ |
| Secure Authentication v5 | ✅ session key change, challenges, aggressive mode, statistics | — | — | symmetric subset with statistics |
| Dual end point (outstation dials) | ✅ | not documented | — | not documented |
| Device attributes (g0) | ✅ both roles, any set | ✅ | — | ✅ |
| TLS | ✅ `crypto/tls` | ✅ | ✅ | ✅ |
| UDP | ✅ | ✅ | ✅ | ✅ |
| Serial | ✅ any byte stream | ✅ | ✅ | ✅ |
| Blocking request methods returning the response | ✅ | — async | — callbacks | not documented |
| Cancellation and deadlines per call | ✅ `context.Context` | futures | — | not documented |
| Structured logging | ✅ `log/slog` | ✅ `tracing` | — own logger | not documented |
| Metrics hooks | ✅ | not documented | — | not documented |
| Dependencies | none | Tokio and others | ASIO | not documented |
| Cross-tested against other stacks in CI | ✅ against all three and dnp3py, every feature they share ([coverage](INTEROPERABILITY.md#interop-coverage)) | not documented | not documented | ✅ opendnp3 (its notes) |

¹ As declared by its adapter in dnp3-interop: the reference container does
not exercise it, which may be the adapter's limit rather than the library's.

✅ = available · — = not available or not documented. For stepfunc dnp3
1.7.0, opendnp3 3.1.2 and DSC go-dnp3 v0.8.1, the versions go-dnp3
is tested against, from their public sources, their documentation and the
[dnp3-interop capability records](https://github.com/otfabric/dnp3-interop),
as of October 2026. If you spot an inaccuracy, please
[open an issue](https://github.com/otfabric/go-dnp3/issues) and we will
correct it.

## Install

```sh
go get github.com/otfabric/go-dnp3
```

Requires Go 1.23 or later. From v1.0.0 the API follows semantic
versioning: a breaking change comes only with a new major version.

## Project structure

| Package | What it is |
|---------|-----------|
| [`dnp3`](https://pkg.go.dev/github.com/otfabric/go-dnp3) | Shared types: sentinel and typed errors, `Logger`, `Metrics`, `State` |
| [`client`](https://pkg.go.dev/github.com/otfabric/go-dnp3/client) | The master |
| [`server`](https://pkg.go.dev/github.com/otfabric/go-dnp3/server) | The outstation and its point database |
| [`app`](https://pkg.go.dev/github.com/otfabric/go-dnp3/app) | Application layer codec and object library |
| [`transport`](https://pkg.go.dev/github.com/otfabric/go-dnp3/transport) | Transport function: segmentation and reassembly |
| [`link`](https://pkg.go.dev/github.com/otfabric/go-dnp3/link) | Data link layer codec: FT3 frames, CRC, stream reader |
| [`secauth`](https://pkg.go.dev/github.com/otfabric/go-dnp3/secauth) | Secure Authentication v5: MACs and the data they protect |

`app`, `transport` and `link` are pure codecs, useful on their own to
analysers and test tools. See [ARCHITECTURE.md](ARCHITECTURE.md).

## Client quickstart

```go
ctx := context.Background()
c, err := client.Dial(ctx, "10.0.0.5:20000",
    client.WithAddresses(1, 10), // master 1, outstation 10
    client.WithReconnect(client.Reconnect{}),
    client.WithRetry(client.Retry{Attempts: 3}),
)
if err != nil {
    log.Fatal(err)
}
defer c.Close()

// An integrity poll: events of classes 1..3, then all static data.
res, err := c.IntegrityPoll(ctx)
if err != nil {
    log.Fatal(err)
}
for _, m := range res.Measurements() {
    switch v := m.Value.(type) {
    case app.Analog:
        fmt.Printf("%s %d = %.2f %s\n", m.GV, m.Index, v.Value, v.Flags)
    case app.Binary:
        fmt.Printf("%s %d = %v\n", m.GV, m.Index, v.Value)
    }
}

// Select-before-operate of a breaker.
if _, err := c.Operate(ctx, client.SelectBeforeOperate, client.CROB(0, app.OpLatchOn, 0, 0)); err != nil {
    var ce *dnp3.CommandError
    if errors.As(err, &ce) {
        log.Printf("refused: %s", ce.Status)
    }
}
```

Unsolicited responses, and every response to an automatic or periodic poll,
go to a `client.Handler`:

```go
c, err := client.Dial(ctx, addr,
    client.WithHandler(client.HandlerFunc(func(info client.ResponseInfo, ms []client.Measurement) {
        for _, m := range ms {
            fmt.Println(info.Unsolicited, m.GV, m.Index, m.Value)
        }
    })),
    client.WithStartup(client.Startup{DisableUnsolicited: true, Integrity: true, EnableUnsolicited: []int{1, 2, 3}}),
    client.WithTimeSync(client.TimeSyncLAN), // when the outstation sets NEED_TIME
)
```

## Server quickstart

```go
breaker := server.HandlerFunc(func(ctx context.Context, c server.Command, op server.OperateType) app.CommandStatus {
    crob, ok := c.Value.(app.CROB)
    if !ok || c.Index != 0 || (crob.Op != app.OpLatchOn && crob.Op != app.OpLatchOff) {
        return app.StatusNotSupported
    }
    // ... operate the device ...
    return app.StatusSuccess
})
srv, err := server.New(
    server.WithAddress(10),
    server.WithMasters(1), // events are buffered for master 1 while it is away
    server.WithHandler(breaker),
    server.WithUnsolicited(server.Unsolicited{Enabled: true}),
)
if err != nil {
    log.Fatal(err)
}
db := srv.Database()
_ = db.AddBinaryInput(0, server.PointConfig{Class: 1}, app.Binary{Value: true, Flags: app.FlagOnline})
_ = db.AddAnalogInput(0, server.PointConfig{Class: 2, StaticVariation: 5, Deadband: 0.5}, app.Analog{Value: 230.1, Flags: app.FlagOnline})

go func() {
    // Updates produce events by change and deadband, in the order they occur.
    _ = db.UpdateAnalogInput(0, app.Analog{Value: 231.0, Flags: app.FlagOnline})
}()
log.Fatal(srv.ListenAndServe(":20000"))
```

## Production features

| Feature | Client | Server |
|---------|--------|--------|
| Cancellation and deadlines | every request takes a `context.Context` | handler calls get a context canceled on `Close` |
| Reconnect | `WithReconnect`: exponential backoff, startup sequence repeated | masters reconnect; their association and events are kept |
| Retries | `WithRetry`: READ, time, unsolicited and class functions only; controls, freezes, restarts and writes never | the master's repeated request is answered with the same response, not executed twice |
| Timeouts | `WithResponseTimeout` per fragment, link layer timeout and retries | `WithConfirmTimeout`, `WithSelectTimeout` |
| Internal indications | clears DEVICE_RESTART, integrity poll on restart and overflow, time sync on NEED_TIME, event poll on class bits | DEVICE_RESTART, NEED_TIME, class events, overflow, broadcast and the request errors maintained; `SetIndications` for local control, device trouble |
| Flow control | one request at a time, as DNP3 requires; `WithQueueLimit` bounds the waiting ones | per-type event limits with oldest-first discard; bounded receive queues |
| Observability | `Logger`, `FieldLogger`, `ContextLogger`, `log/slog`; `Metrics`, `RequestMetrics`; state handler | `Logger`; `Metrics`, `ServerMetrics` |
| Security | TLS, Secure Authentication v5 with aggressive mode and re-keying after a failure | TLS, Secure Authentication v5 with a reply timeout and security statistics, master address filter |

## Transports

| Transport | Client | Server |
|-----------|--------|--------|
| TCP | default | `ListenAndServe`, `Serve` |
| TLS | `WithTLS` | `WithTLS` with `ListenAndServe`, or a TLS listener with `Serve` |
| UDP | `WithStream(client.UDP(addr))` | `ServeUDP`, or `ServeUDPTo` with the master's address |
| Serial, or any byte stream | `WithStream` with an opener that returns the port | `ServeConn` |
| Dual end point (the outstation connects) | `WithStream(client.Accept(l))` | `DialAndServe(ctx, masterAddr, server.Redial{})` |

Serial ports are not opened by this module, so that it has no
dependencies: open the port with a serial library, for example
[otfabric/go-serial](https://github.com/otfabric/go-serial), and hand it
over:

```go
c, err := client.Dial(ctx, "/dev/ttyUSB0", client.WithStream(func(ctx context.Context) (io.ReadWriteCloser, net.Addr, error) {
    p, err := serial.Open(&serial.Config{Address: "/dev/ttyUSB0", BaudRate: 19200})
    return p, nil, err
}))
```

Leave the port's read timeout at zero (blocking reads): a read that times
out is a failing stream to the channel, which then closes. Inactivity is
detected by the link layer's keep-alive instead (`client.Link.KeepAlive`).

## The object model

Responses are decoded into `app.Fragment` values: headers (`app.Header`)
with their objects (`app.Object`), each an index and a value. The values
are a closed set of structs: `app.Binary`, `app.DoubleBitBinary`,
`app.Counter`, `app.Analog`, `app.CROB`, `app.AnalogOutput`,
`app.OctetString`, the file and authentication objects and a few more. One
struct serves every variation of a kind of point; the header's
`app.GroupVariation` (constants such as `app.G30V5`) says how it is
encoded. Time stamps are `app.Timestamp`, DNP3's milliseconds since 1970,
with conversions to and from `time.Time`.

Encoding an analog value into an integer variation rounds it; a value the
variation cannot hold is sent as the nearest one with OVER_RANGE set,
while a set-point that does not fit is refused. See the [`app` package
documentation](https://pkg.go.dev/github.com/otfabric/go-dnp3/app).

## Error semantics

Errors are sentinels tested with `errors.Is` (`dnp3.ErrTimeout`,
`dnp3.ErrConnectionLost`, `dnp3.ErrNotConnected`, `dnp3.ErrClosed`, ...)
and typed errors for answers of the outstation, matched with `errors.As`:
`*dnp3.IINError` (the request was refused), `*dnp3.CommandError` (a control
was not executed), `*dnp3.FileError` and `*dnp3.AuthError`. Request methods
return the response together with an `IINError`, so that what the
outstation did report is not lost. See [ERRORS.md](ERRORS.md).

## Examples

Runnable programs under [examples/](examples/): seven self-contained ones
(`quickstart`, `commands`, `events`, `files`, `secure`, `observability`,
`dialout`)
that start both sides in one process, and a standalone `server` and
`client` for trying the library against other implementations. See
[examples/README.md](examples/README.md).

```sh
go run ./examples/quickstart
```

## Development

```sh
make check   # format, lint, vet, vulnerability scan, race tests, coverage, examples
make test    # the tests with the race detector
make fuzz    # the codec and outstation fuzz targets (FUZZTIME=30s each by default)
make bench   # the codec benchmarks
```

Tests need nothing but Go: master and outstation run against each other
and against scripted peers over loopback, including a chaos suite that
corrupts, duplicates and drops octets on the line, and stress tests with
many masters and concurrent requests. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Interop tests

`make interop` runs go-dnp3 as master against the reference outstations,
and the reference masters against go-dnp3's outstation, using the images
of [otfabric/dnp3-interop v0.4.1](https://github.com/otfabric/dnp3-interop/releases/tag/v0.4.1),
pinned by digest:

| Reference | Version | Licence | Roles tested |
|-----------|---------|---------|--------------|
| Step Function I/O dnp3 | 1.7.0 | non-commercial | master and outstation |
| opendnp3 | 3.1.2 | Apache-2.0 | master and outstation |
| DSC go-dnp3 | v0.8.1 | GPL-3.0 | master and outstation |
| dnp3py | 0.6.0 | MIT | master and outstation (its outstation serves the dnp3py fixture only) |

Both directions cover the integrity poll against the fixture's values and
flags, reads of ranges and variations, every control case of the fixture
(select-before-operate, select-required outputs, set-point ranges,
unsupported codes and points), events and their confirmation, unsolicited
responses, both time synchronization procedures, cold and warm restarts,
freeze and clear, and assign class. The transports and procedures of
dnp3-interop's contracts 1.1 to 1.3 are tested in both directions where a
reference has the feature (see the matrix): TLS with mutual authentication (a test PKI is
generated per run), UDP, serial lines (a pseudo-terminal in the container
bridged to TCP), file transfer against the files fixture, and Secure
Authentication with session key changes and the security statistics; also
the requests without a response (DIRECT OPERATE NO ACK, the `_NR`
freezes), reads of all objects of a group, and contract 1.2: the dual end
point over TCP and TLS, frozen analog inputs, command events, time and
interval, security statistic events, and the dnp3py fixture; and contract
1.3: device attribute sets, several controls in one request, scheduled
freezes and analog freeze, deadbands, file append and authentication, event
buffer overflow, link confirms and keep-alive, broadcast, the management
functions and several outstations behind one port. The
[coverage matrix](INTEROPERABILITY.md#interop-coverage) shows each feature
per reference and direction. Deviations a reference has from the
fixture are those dnp3-interop records as known bugs. Docker is needed; the
images are consumed as published, nothing of dnp3-interop is built here.

The third-party code runs in its own container only: nothing of it is
linked into go-dnp3.

## Limitations

- **Secure Authentication**: update keys are configured out of band. The
  remote update key change, user management (certificates, user status
  change) and AES-GMAC are not implemented; aggressive mode is verified
  between go-dnp3's ends only, as no reference stack in the interop suite
  has it. See [SECURITY.md](SECURITY.md) and
  [the gaps](INTEROPERABILITY.md#feature-completeness-and-the-remaining-gaps).
- **Data sets, private registration objects and the virtual terminal**
  (groups 83, 85..88, 90, 91 raw; 112, 113 decoded) have no procedures:
  exchange them with the generic request methods.
- **Several outstations behind one port**: a `Server` is one outstation;
  serve several on their own ports.
- **UDP outstation**: one socket serves one master at a time; a master
  behind another address takes it over when it sends.
- **Multi-fragment requests** are not reassembled by the outstation: a
  request is one fragment.

## License

[MIT](LICENSE). The reference implementations the interop tests run are
under their own licences and are not part of this module.
