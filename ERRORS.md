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
| Dial, TLS or stream opener failed | wraps `dnp3.ErrConnectFailed` and the cause: the error of a `WithDialer` dialer, so `errors.Is` finds its own sentinels (an allowlist's refusal); a dialer that returned neither a connection nor an error | `errors.Is` |
| The client or server was closed | `dnp3.ErrClosed` | `errors.Is` |
| Too many requests waiting; `Connect` while connected | wraps `dnp3.ErrBusy` | `errors.Is` |
| A response with NO_FUNC_CODE_SUPPORT, OBJECT_UNKNOWN, PARAMETER_ERROR or ALREADY_EXECUTING | `*dnp3.IINError` | `errors.As` |
| A control echoed with a status other than SUCCESS, or a control response cut at the first failed object (4.4.4.3 Rule 6) | `*dnp3.CommandError` with that status | `errors.As` |
| A file operation refused | `*dnp3.FileError` | `errors.As` |
| An authentication error from the peer | `*dnp3.AuthError`, matches `dnp3.ErrAuthentication`; also from a no-ack request whose challenge reply was refused | `errors.As`, `errors.Is` |
| A challenge without secure authentication configured, for another MAC algorithm (an 8-octet MAC over TCP/UDP unless `WithChallengeMACs` allows it), or before the session keys were changed | wraps `dnp3.ErrAuthentication` (with an update key, the client then changes the keys at once) | `errors.Is` |
| A critical request while the session keys are not valid yet, with an update key: a function Table 7-7 marks MANDATORY, or one `WithAggressiveMode` names | wraps `dnp3.ErrAuthentication`; the request is not sent, and the client changes the keys at once | `errors.Is` |
| An aggressive mode request, or a challenge reply that came too late, refused | `*dnp3.AuthError`, matches `dnp3.ErrAuthentication` | `errors.As`, `errors.Is` |
| A session key change whose key status is not authentic (wrong MAC with the last monitoring key), names another user or key wrap algorithm, or whose confirmation is not OK | wraps `dnp3.ErrAuthentication` | `errors.Is` |
| A response that does not fit the request (a control echo that differs, a missing or unexpected object, a wrong file block, a directory listing longer than 16 MiB, a response longer than `WithMaxResponse`, 16 MiB by default, an `ActivateConfig` response without a valid g91v1 status) | wraps `dnp3.ErrProtocol`. Awaiting the first fragment, one with another sequence number or without FIR is ignored; during a multi-fragment response, an unexpected fragment abandons the response with `ErrProtocol` (Table 6-2); a SELECT echo that differs from the request in any octet is `ErrProtocol`, and no OPERATE is sent | `errors.Is` |
| Headers of a request that do not encode | the `app` codec error (for example `app.ErrInvalidValue`) | `errors.Is` |
| Application code that does not return normally: a `Dialer`, `StreamOpener`, the listener of `Accept`, or a `tls.Config` callback while connecting; the `io.Writer` of `ReadFile` or the `io.Reader` of `WriteFile` | connecting: wraps `dnp3.ErrConnectFailed`; a transfer: an error whose message names the code (`io.Writer of ReadFile did not return normally: ...`), and the transfer is aborted. Logged with its stack | `errors.Is` |
| An option or argument that cannot be used, a request larger than `WithMaxRequestFragment`, a `Command` with Queue set or a status other than 0 or 126, a `TimeSync` value beyond `TimeSyncClearNeedTime` | wraps `dnp3.ErrInvalidOption` | `errors.Is` |
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

A NACK with DFC set to a confirmed frame (`Link.Confirmed`) fails the
send with `ErrProtocol` ("secondary station is busy"); the frame is not
repeated (Table 9-6).

On the outstation, a connection ends with:

- `ErrClosed` when its master is already connected over another
  connection that answers a link status request (13.2.3.3);
- `ErrConnectionLost`, "replaced by a new connection", for the old
  connection that did not answer it;
- `ErrTimeout` when no master sent a frame within the keep-alive interval
  and the link timeout.

`server.WithMasterIPs` without a prefix or with an invalid one,
`ServeByMasterIP` without routes, with an invalid prefix or without
exactly one target in a route, `ServeUDPFixed` with a peer that is not a
UDP address, `server.WithFileTimeout` with a timeout of 0 or less or a
class outside 1..3, and `client.WithDualEndpoint` with a nil listener or
together with `WithStream` fail with `ErrInvalidOption`.

A `Connect` whose startup sequence fails (a refused session key change, an
integrity poll without an answer) returns that error and closes the
channel: the client is `StateDisconnected`. A step the outstation answers
with an error IIN (an `IINError`, such as IIN2.0 to DISABLE_UNSOLICITED from
an outstation without unsolicited responses) does not fail it: it is logged
(`startup step rejected`) and the sequence goes on. A channel the client
re-established itself is kept even when its startup sequence failed.

## Codec errors

The codecs report what they cannot parse or encode with their own
sentinels: `app.ErrMalformed`, `app.ErrUnknownObject`,
`app.ErrInvalidQualifier`, `app.ErrUnknownFunction`, `app.ErrInvalidValue`;
the `transport` and `link` sentinels of the table below. A master never returns them
for what it receives: a fragment it cannot decode is dropped and reported
to `Metrics.OnDecodeError` (`ListDirectory` wraps the codec error of a
listing that does not decode together with `ErrProtocol`, and
`ActivateConfig` the `app.ErrMalformed` of a g91v1 status that does not
parse). `app.ParseActivateConfigStatus` fails with `app.ErrMalformed`, and
`app.ActivateConfigStatus.Raw` with `app.ErrInvalidValue` for a status that
does not fit the object; an outstation answers an `ActivateConfigHandler`
status that does not encode, or does not fit a fragment, with
PARAMETER_ERROR. `app.Fragment.Encode` fails with `app.ErrInvalidValue`
for a BCD value that does not fit its variation, a floating-point
attribute of a size other than 4 or 8 octets, a g81v1 fill above 127, and,
in a response, a group 60 or variation 0 header (`app.ErrInvalidQualifier`
for qualifier 0x06). `app.Decode` reports the same headers in a response,
a floating-point attribute of another size and a BCD sign character
outside the most significant position with `app.ErrMalformed`
(`app.ErrInvalidQualifier` for qualifier 0x06). A request whose
own headers do not encode fails with the codec error itself. An outstation
answers a request it cannot decode with the IIN2 bit the standard prescribes (OBJECT_UNKNOWN for
`ErrUnknownObject`, NO_FUNC_CODE_SUPPORT for `ErrUnknownFunction`,
PARAMETER_ERROR otherwise).

| Sentinel | Meaning |
|----------|---------|
| `link.ErrFraming` | Wrapped by every error for a damaged or invalid frame, together with one of the five below. The stream stays usable |
| `link.ErrInvalidStart` | The frame does not begin with 0x05 0x64; `link.Reader` also reports the octets it skipped to resynchronize |
| `link.ErrInvalidLength` | A length octet below 5, more user data than a frame holds, or a length that does not fit the function |
| `link.ErrCRC` | The CRC of the header or of a data block does not match |
| `link.ErrInvalidFunction` | A function code the standard does not define for the frame's direction (primary or secondary) |
| `link.ErrShortBuffer` | The buffer holds only part of a frame: more input can complete it |
| `transport.ErrEmpty` | A segment without a header octet |
| `transport.ErrNoFirst` | A segment without FIR while no fragment was being assembled |
| `transport.ErrSequence` | A segment whose sequence number does not follow the previous one; the partial fragment is discarded |
| `transport.ErrDuplicate` | A segment that repeats the previous one octet for octet (Table 8-1); it is discarded and the fragment goes on. Not an error of the channel |
| `transport.ErrNoData` | A segment with a transport header and no data octets (8.2.2) |
| `transport.ErrTooLarge` | A fragment grew beyond the reassembler's limit and is discarded |
| `secauth.ErrKeyWrap` | Wrapped key data does not unwrap: a wrong key, damaged data, a failed integrity check, a wrong session key length, or a key status message that differs from the last one sent |

`Reassembler.Add` stays usable after each `transport` error.

## Context and timeouts

Every request is bounded by its context and by the response timeout, per
fragment. Whichever ends first decides the error: the context's own error,
or one wrapping `ErrTimeout`. A canceled request does not cancel what the
outstation already received; a control that timed out may have been
executed.

With secure authentication, an outstation stops sending error messages past
Max Error Messages Sent (3 by default) until the next session key change: a
master with a wrong key then gets `dnp3.ErrTimeout` instead of
`*dnp3.AuthError`.

## Retries

`WithRetry` repeats a request that failed with `ErrTimeout`,
`ErrConnectionLost` or `ErrNotConnected`, while its context lives, with
exponential backoff, randomized by `Retry.Jitter` when it is set (a jitter
outside 0 to 1 fails the option with `ErrInvalidOption`; `Reconnect.Jitter`
likewise). Only requests that are safe to repeat are retried:
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
| A frame of a new master address beyond `WithMaxAssociations` | dropped; `Metrics.OnDecodeError`; a debug entry |
| A `Database.Batch` function that does not return normally | `Batch` returns an error whose message names it; no events are reported; logged with its stack |
| Events discarded because the buffer was full | EVENT_BUFFER_OVERFLOW; `ServerMetrics.OnEventsDiscarded`; a warning |
| An unsolicited response that was never confirmed | `ServerMetrics.OnUnsolicited` with an error wrapping `ErrTimeout`; the events are reported later |
| A failed authentication, a late reply, a refused key change or aggressive mode request | an authentication error object to the master; a warning; the security statistics (g121, g122 events) |
| `ListenAndServe`, `Serve`, `ServeConn`, `ServeUDP`, `ServeUDPTo` | return the listener's or stream's error; `nil` when `Close` ends them, `dnp3.ErrClosed` when called after `Close`. `Serve` keeps accepting after an `Accept` error other than a closed listener (running out of file descriptors, for one), after a pause; a UDP socket keeps serving after an error that concerns one datagram (an ICMP unreachable, a send to a route that went away) |
| A TLS handshake of an accepted connection that takes longer than 10 s | the connection is closed and logged (`TLS handshake failed`); it does not hold a connection slot |
| `DialAndServe` | returns `ctx.Err()` when ctx ends and `nil` after `Close`, and `dnp3.ErrInvalidOption` at once for a `Redial.Jitter` outside 0 to 1; failed dials, TLS handshakes and lost connections are retried, not returned: the `error` of their log record wraps `dnp3.ErrConnectFailed` and the dialer's or handshake's error |

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
