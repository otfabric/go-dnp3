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
fields of its context: `remote` and `outstation` for a client; for a
server `outstation`, with `remote` on the entries of a connection and
`master` on those of a master's association. With a plain `Logger` the
same fields are a prefix of the formatted line.

Debug entries are built only when the logger says it takes them: a logger
with a `DebugEnabled() bool` method is asked, and the slog adapters ask
their handler, so the per-frame and per-fragment entries cost nothing at
info level. Any other logger, `NewStdLogger` and `NopLogger` included,
receives every debug entry, one per frame and fragment; leave `WithLogger`
out to log nothing.

### Context

When the logger implements `dnp3.ContextLogger`, entries that belong to a
request (a retry, the request itself and a broadcast at debug level) are logged with the
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
| info | `session keys changed` | `user` |
| info | `connection to the master lost, reconnecting` (`DialAndServe`, also after a failed dial) | `address`, `error`, `delay` |
| warn | `connection lost`, `reconnect failed` | `error`, `retry_in` |
| warn | `request failed, retrying` | `function`, `attempt`, `retry_in`, `error` |
| warn | `automatic task failed` | `task`, `error` |
| warn | `startup sequence failed` | `error` |
| warn | `startup step rejected` (the outstation answered a startup step with an error IIN; the sequence goes on) | `step`, `error` |
| warn | `event buffer overflow` | `master`, `class`, `discarded` |
| warn | `keep-alive failed` | `remote_addr`, `error` |
| warn | `authentication failed`, `challenge reply too late`, `aggressive mode request refused` | `user`, `csq` |
| warn | `session key change refused` | `user`, `ksq` |
| warn | `session key change failed` | `user`, `error` |
| warn | `authentication error received` | `user`, `code` |
| warn | `objects too large for a fragment left out` | `count` |
| warn | `connection refused: limit reached` | `remote`, `limit` |
| warn | `accept failed` (the listener keeps accepting after a pause) | `error` |
| warn | `TLS handshake failed` (also when it took longer than 10 s) | `remote`, `error` |
| warn | `fragment dropped` | `error` |
| warn | `multi-fragment request ignored` | `control` |
| warn | `frame with invalid FCV bit ignored` | `frame` |
| warn | `unauthenticated critical broadcast discarded` | `function` |
| info | `confirmed user data while the link is not reset ignored` | |
| error | `no random challenge data`, `key status MAC` | `error` |
| error | `response does not encode` | `fragment`, `error` |
| error | `panic while serving a request`, `panic while receiving a fragment` (the request or fragment is lost; the association, client and process go on) | `panic`, `stack` |
| debug | `challenge answered` | `csq`, `user` |
| debug | `frame sent`, `frame received` | `frame` |
| debug | `request sent`, `request received`, `response sent`, `fragment received` | `fragment` |
| debug | `broadcast sent` | `fragment`, `dest` |
| debug | framing, transport and decode errors; ignored frames and fragments | `error`, ... |

## Metrics

`WithMetrics` takes a `dnp3.Metrics`. Its methods are called synchronously
on the protocol path, possibly from several goroutines at once: they must
be safe for concurrent use and must not block. Embed `dnp3.NopMetrics` to
implement only what you need.

| Callback | When |
|----------|------|
| `OnConnect(remote)` | A channel started |
| `OnDisconnect(remote, err)` | A channel ended; `err` nil when closed by the application, or by `Connect` after a failed startup sequence (`Connect` returns that error) |
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

Secure Authentication has no metrics callback: the outstation's security
statistics are its counters. Any master reads them as g121v1 (indexes in
`secauth.Statistic`), and `SecureAuth.StatisticsThreshold` turns them into
g122 events; the warnings above name each failure.

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
that caused it, nil when the application closed the client, and again with
`StateConnecting` for each failed reconnect attempt. Notifications are
delivered in order, on the client's dispatcher goroutine together with the
measurements; the last one (`StateDisconnected` from `Close`) is called by
`Close` itself, after every earlier one, before it returns. `(*Client).State()` returns the current state at any time.
