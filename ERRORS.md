# Errors: otfabric/go-dnp3

How failures are reported, and how to tell them apart.

## Table of contents

- [Quick reference](#quick-reference)
- [Sentinels](#sentinels)
- [Refusals by the outstation](#refusals-by-the-outstation)
- [Connection errors](#connection-errors)
- [Codec errors](#codec-errors)
- [Context and timeouts](#context-and-timeouts)
- [Retries](#retries)
- [What the outstation reports instead of an error](#what-the-outstation-reports-instead-of-an-error)
- [Detection patterns](#detection-patterns)

## Quick reference

| Situation | Error | Test with |
|-----------|-------|-----------|
| The outstation did not answer in time | wraps `dnp3.ErrTimeout` | `errors.Is` |
| The connection ended during the request | wraps `dnp3.ErrConnectionLost` | `errors.Is` |
| No connection | `dnp3.ErrNotConnected` | `errors.Is` |
| Dial, TLS or stream opener failed | wraps `dnp3.ErrConnectFailed` and the cause | `errors.Is` |
| The client or server was closed | `dnp3.ErrClosed` | `errors.Is` |
| Too many requests waiting; `Connect` while connected | wraps `dnp3.ErrBusy` | `errors.Is` |
| A response with NO_FUNC_CODE_SUPPORT, OBJECT_UNKNOWN, PARAMETER_ERROR or ALREADY_EXECUTING | `*dnp3.IINError` | `errors.As` |
| A control echoed with a status other than SUCCESS | `*dnp3.CommandError` | `errors.As` |
| A file operation refused | `*dnp3.FileError` | `errors.As` |
| An authentication error from the peer | `*dnp3.AuthError`, matches `dnp3.ErrAuthentication` | `errors.As`, `errors.Is` |
| A challenge without secure authentication configured, for another MAC algorithm, or before the session keys were changed | wraps `dnp3.ErrAuthentication` (with an update key, the client then changes the keys at once) | `errors.Is` |
| An aggressive mode request, or a challenge reply that came too late, refused | `*dnp3.AuthError`, matches `dnp3.ErrAuthentication` | `errors.As`, `errors.Is` |
| A response that does not fit the request (a control echo that differs, a missing or unexpected object, a wrong file block) | wraps `dnp3.ErrProtocol`; a fragment with an unexpected sequence number is ignored, so the request times out | `errors.Is` |
| Headers of a request that do not encode | the `app` codec error (for example `app.ErrInvalidValue`) | `errors.Is` |
| An option or argument that cannot be used | wraps `dnp3.ErrInvalidOption` | `errors.Is` |
| `Client.Broadcast` | only local errors: `ErrInvalidOption` (not a broadcast address, a function that needs an answer), `ErrNotConnected`, send errors; the outstations answer nothing, IIN1.0 shows in their next response | `errors.Is` |
| The caller's context ended | `context.Canceled`, `context.DeadlineExceeded` | `errors.Is` |

## Sentinels

The sentinels of package `dnp3` are wrapped with detail, so always test
with `errors.Is`, never with `==`. The message of a wrapped error is for
people and may change; the sentinel is the contract.

## Refusals by the outstation

An outstation refuses a request with IIN2 bits. The methods that return a
`*Result` (`Read`, `IntegrityPoll`, `EventPoll`, `Write`, `Request`) return
it **and** an `*IINError`, so that what the outstation did report is still
available; the other methods return only the error:

```go
res, err := c.Read(ctx, app.IndexRange(app.G1V2, 0, 9))
var ie *dnp3.IINError
if errors.As(err, &ie) && ie.IIN.Has(app.IINParameterError) {
    // Some of 0..9 do not exist; res holds the ones that do.
    use(res.Measurements())
}
```

A control the outstation did not execute is a `*CommandError` with the
status it echoed (NO_SELECT, LOCAL, OUT_OF_RANGE, NOT_SUPPORTED, ...).
`Operate` returns the statuses of all controls with a `*CommandError`, in
order; the error names the first one that failed. With select-before-operate a failed SELECT
ends the operation: the OPERATE is not sent.

Some outstations set PARAMETER_ERROR together with a NOT_SUPPORTED echo; the
response then fails with an `*IINError`. Test for both when the reason does
not matter.

## Connection errors

`ErrConnectionLost` wraps the stream's error: an end of stream by the peer,
a failed write, a keep-alive that went unanswered (that one wraps
`ErrTimeout` too). The request that was waiting fails with it; a client with
`WithReconnect` reconnects, and the next request can succeed.

A `Connect` whose startup sequence fails (a refused session key change, an
integrity poll without an answer) returns that error and closes the
channel: the client is `StateDisconnected`. A channel the client
re-established itself is kept even when its startup sequence failed.

## Codec errors

The codecs report what they cannot parse or encode with their own
sentinels: `app.ErrMalformed`, `app.ErrUnknownObject`,
`app.ErrInvalidQualifier`, `app.ErrUnknownFunction`, `app.ErrInvalidValue`;
`transport.ErrSequence` and friends; `link.ErrFraming` and the specific
framing errors it is wrapped together with. A master never returns them
for what it receives: a fragment it cannot decode is dropped and reported
to `Metrics.OnDecodeError` (`ListDirectory` wraps the codec error of a
listing that does not decode together with `ErrProtocol`). A request whose
own headers do not encode fails with the codec error itself. An outstation
answers a request it cannot decode with the IIN2 bit the standard prescribes (OBJECT_UNKNOWN for
`ErrUnknownObject`, NO_FUNC_CODE_SUPPORT for `ErrUnknownFunction`,
PARAMETER_ERROR otherwise).

## Context and timeouts

Every request is bounded by its context and by the response timeout, per
fragment. Whichever ends first decides the error: the context's own error,
or one wrapping `ErrTimeout`. A canceled request does not cancel what the
outstation already received; a control that timed out may have been
executed.

## Retries

`WithRetry` repeats a request that failed with `ErrTimeout`,
`ErrConnectionLost` or `ErrNotConnected`, while its context lives, with
exponential backoff. Only requests that are safe to repeat are retried:
READ, time synchronization, delay measurement, unsolicited control, assign
class, the session key change, file info and the block reads of a file
transfer (not OPEN_FILE or CLOSE_FILE). Controls, freezes, restarts and writes are
never repeated. An `IINError` is never retried: the outstation answered.
`RequestMetrics.OnRetry` reports each repeated attempt.

## What the outstation reports instead of an error

The server has no request methods to fail; it answers. What goes wrong in a
request becomes IIN bits or command statuses in the response, and what goes
wrong on the connection ends it. The server reports to its application
through:

| Situation | Where it shows |
|-----------|----------------|
| A request it could not decode | IIN2 bits in the response; `Metrics.OnDecodeError` |
| Events discarded because the buffer was full | EVENT_BUFFER_OVERFLOW; `ServerMetrics.OnEventsDiscarded`; a warning |
| An unsolicited response that was never confirmed | `ServerMetrics.OnUnsolicited` with an error wrapping `ErrTimeout`; the events are reported later |
| A failed authentication, a late reply, a refused key change or aggressive mode request | an authentication error object to the master; a warning; the security statistics (g121, g122 events) |
| `ListenAndServe`, `Serve`, `ServeConn`, `ServeUDP`, `ServeUDPTo` | return the listener's or stream's error; `nil` when `Close` ends them, `dnp3.ErrClosed` when called after `Close` |
| `DialAndServe` | returns `ctx.Err()` when ctx ends and `nil` after `Close`; failed dials, TLS handshakes and lost connections are retried, not returned |

## Detection patterns

```go
var commandErr *dnp3.CommandError
var iinErr *dnp3.IINError
switch _, err := c.Operate(ctx, client.SelectBeforeOperate, cmd); {
case err == nil:
case errors.As(err, &commandErr):
    // the outstation refused the control: commandErr.Status
case errors.As(err, &iinErr):
    // the outstation refused the request: iinErr.IIN
case errors.Is(err, dnp3.ErrTimeout):
    // no answer: the control may or may not have been executed
case errors.Is(err, dnp3.ErrConnectionLost), errors.Is(err, dnp3.ErrNotConnected):
    // the link is down
case errors.Is(err, dnp3.ErrAuthentication):
    // wrong key, or secure authentication not configured
}
```
