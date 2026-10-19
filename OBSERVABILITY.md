# Observability: otfabric/go-dnp3

Logging, metrics and state notifications of the client and the server.

## Contents

- [Logging](#logging)
- [Metrics](#metrics)
- [Connection state](#connection-state)

## Logging

Logging is silent by default. Give a `dnp3.Logger` with `WithLogger`; the
library has four adapters:

| Constructor | Result |
|-------------|--------|
| `dnp3.NopLogger()` | discards everything |
| `dnp3.NewStdLogger(*log.Logger)` | one formatted line per entry, prefixed with the level |
| `dnp3.NewSlogLogger(slog.Handler)` | structured entries through `log/slog` |
| `dnp3.NewSlogFieldLogger(slog.Handler)` | the same, typed as a `FieldLogger` to add fields with `With` |

### Structured logging

When the logger also implements `dnp3.FieldLogger`, every entry is a
constant message plus fields, never one formatted string, so it can be
filtered and counted:

```go
logger := dnp3.NewSlogLogger(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
c, err := client.Dial(ctx, addr, client.WithLogger(logger))
```

Every entry carries `component` (`dnp3.client` or `dnp3.server`) and the
fields of its context: `remote` and `outstation` for a client, `outstation`,
`remote` and `master` for a server.

Debug entries are built only when the handler takes debug entries
(`DebugEnabled`): the per-frame and per-fragment entries cost nothing at
info level.

### Context

When the logger implements `dnp3.ContextLogger`, entries that belong to a
request (a retry, the request itself at debug level) are logged with the
request's context, so that a handler can attach trace and span
identifiers.

### Entries

| Level | Message | Fields |
|-------|---------|--------|
| info | `connected`, `connection opened`, `connection closed` | `remote_addr`, `remote`, `error` |
| info | `listening` | `address` |
| info | `time synchronized` | `time` |
| info | `master reconnected, closing its previous connection` | |
| info | `unsolicited response given up` | `seq`, `events` |
| warn | `connection lost`, `reconnect failed` | `error`, `retry_in` |
| warn | `request failed, retrying` | `function`, `attempt`, `retry_in`, `error` |
| warn | `automatic task failed`, `startup sequence failed` | `task`, `error` |
| warn | `event buffer overflow` | `master`, `class`, `discarded` |
| warn | `keep-alive failed` | `remote_addr`, `error` |
| warn | `authentication failed` | `user`, `csq` |
| warn | `connection refused: limit reached` | `remote`, `limit` |
| warn | `fragment dropped`, `multi-fragment request ignored`, `frame with invalid FCV bit ignored` | |
| debug | `frame sent`, `frame received` | `frame` |
| debug | `request sent`, `request received`, `response sent`, `fragment received` | `fragment` |
| debug | framing, transport and decode errors; ignored frames and fragments | `error`, ... |

## Metrics

`WithMetrics` takes a `dnp3.Metrics`. Its methods are called synchronously
on the protocol path, possibly from several goroutines at once: they must
be safe for concurrent use and must not block. Embed `dnp3.NopMetrics` to
implement only what you need.

| Callback | When |
|----------|------|
| `OnConnect(remote)` | A channel started |
| `OnDisconnect(remote, err)` | A channel ended; `err` nil when closed by the application |
| `OnFrameSent(remote, frame, size)`, `OnFrameReceived` | Every link frame |
| `OnFramingError(remote, err)` | Octets skipped or a frame discarded: start, length, CRC |
| `OnFragmentSent(remote, fragment, size)`, `OnFragmentReceived` | Every application fragment |
| `OnDecodeError(remote, err)` | A segment or fragment that could not be decoded, or a full receive queue |

Frames and fragments passed to the callbacks must not be kept or modified.

### Request and server metrics

A value that also implements `dnp3.RequestMetrics` (client) receives one
`OnRequest` before the first attempt, one `OnRequestDone` with the final
outcome and the total duration, retries and their pauses included, and an
`OnRetry` for each attempt that is repeated. Requests of automatic tasks and
periodic polls are reported the same way.

A value that also implements `dnp3.ServerMetrics` (server) receives
`OnHandled(remote, function, duration)` after each request,
`OnEventsDiscarded(class, n)` on buffer overflow and `OnUnsolicited(remote,
events, err)` when an unsolicited response was confirmed or given up.

```go
type counters struct {
    dnp3.NopMetrics
    timeouts atomic.Int64
}

func (m *counters) OnRequest(net.Addr, uint16, app.FunctionCode) {}
func (m *counters) OnRetry(net.Addr, uint16, app.FunctionCode, int, error) {}
func (m *counters) OnRequestDone(_ net.Addr, _ uint16, _ app.FunctionCode, _ time.Duration, err error) {
    if errors.Is(err, dnp3.ErrTimeout) {
        m.timeouts.Add(1)
    }
}
```

## Connection state

`client.WithStateHandler` is called with each change of the channel state
(`StateConnecting`, `StateConnected`, `StateDisconnected`) and the error
that caused it, nil when the application closed the client. Notifications
are delivered in order, on the client's dispatcher goroutine together with
the measurements, and the last one (`StateDisconnected` from `Close`) before
`Close` returns. `(*Client).State()` returns the current state at any time.
