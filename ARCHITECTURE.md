# Architecture: otfabric/go-dnp3

How the module is divided, why, and how a request travels through it.

## Layers

DNP3 has three layers, and the module follows them:

```text
                       IEEE 1815-2012
┌──────────────────────────────────────────────────────┐
│  Application layer   fragments: control octet,       │  package app
│                      function code, IIN, object      │  (codec, object library)
│                      headers, objects                │  client, server (procedures)
├──────────────────────────────────────────────────────┤
│  Transport function  segments of up to 249 octets,   │  package transport
│                      FIR / FIN / sequence             │
├──────────────────────────────────────────────────────┤
│  Data link layer     FT3 frames, CRC per 16 octets,  │  package link (codec)
│                      addresses, primary/secondary,   │  internal/channel (procedures)
│                      frame count bit, link status    │
└──────────────────────────────────────────────────────┘
       TCP, TLS, UDP or any byte stream (serial)
```

- **The codecs are exported and pure.** `link`, `transport` and `app` do no
  I/O beyond `link.Reader` over an `io.Reader`, keep no state across
  frames (the transport `Segmenter` and `Reassembler` keep only their
  sequence numbers) and import nothing outside the standard library.
- **The procedures are internal.** The link layer procedures run in
  `internal/channel`, whose API is shaped by the client and the server and
  nothing else. The application layer procedures live in `client` and
  `server`, where they meet the application.
- **`secauth`** holds the cryptography of Secure Authentication; the
  challenge-reply exchange is part of the client and the server.

## Packages and import rules

```text
dnp3 (root)          errors, State, Logger, Metrics          imports: app, link
  ├── link           frames, CRC, Reader                       imports: nothing
  ├── transport      segmentation, reassembly                  imports: nothing
  ├── app            fragments, headers, objects               imports: nothing
  ├── secauth        MACs, authenticated data                   imports: app
  ├── internal/logx  structured or formatted log entries        imports: root
  ├── internal/channel  link procedures, sessions               imports: root, link, transport, logx
  ├── client         master                                     imports: root, app, link, secauth, channel, logx
  └── server         outstation                                 imports: root, app, link, secauth, channel, logx
```

`client` and `server` never import each other; their tests do, to use the
other side as a peer.

## The channel

A `channel.Channel` owns one byte stream and one reader goroutine.
Frames are routed by their address pair to a `channel.Session`: one
association of a master and an outstation. Several sessions share a channel
on a multi-drop serial line; on TCP there is usually one.

```text
                         ┌───────────────────────────────────────────┐
 stream ─► reader ──────►│ Session (one per address pair)            │
          goroutine      │  secondary: reset state, expected FCB,    │──► OnFragment
          (link.Reader)  │    ACK / LINK_STATUS / NOT_SUPPORTED      │    (session goroutine,
                         │  reassembler ─► queue of fragments        │     in order)
                         │  primary: Send(fragment) → segments →     │
 Send ──────────────────►│    frames; confirmed: RESET_LINK_STATES,  │──► stream
                         │    FCB toggling, retries; keep-alive      │    (one writer lock)
                         └───────────────────────────────────────────┘
```

- **The reader answers the link layer itself.** ACKs, link status and the
  frame count bit are handled on the reader goroutine, which never waits for
  the application: completed fragments go into a bounded queue that a
  goroutine per session drains into `OnFragment`. A slow application can
  delay its own fragments but never a link layer answer.
- **One primary transaction at a time per session.** `Send` holds the
  session's primary lock for a whole fragment, so that segments of two
  fragments never interleave and a confirmed frame's ACK is matched to it.
- **Resynchronisation** is the reader's: octets before a start sequence are
  skipped, a header with a bad CRC is left one octet at a time, a frame
  with a bad data CRC is discarded whole. Each is reported as an error that
  wraps `link.ErrFraming`, so metrics count them and the stream goes on.
- **Keep-alive**: after `KeepAlive` without a received frame the session
  sends REQUEST_LINK_STATUS; a peer that does not answer closes the channel
  with `dnp3.ErrTimeout`.

## Client

`client.Client` holds at most one channel and adds:

- **Connection lifecycle**: `Connect` opens the stream (dial, TLS
  handshake, or a `StreamOpener`), starts the channel and runs the startup
  sequence. With `WithReconnect` a goroutine waits for the channel to end
  and reconnects with exponential backoff.
- **One transaction at a time.** DNP3 allows a single outstanding request
  per association. A one-slot semaphore admits requests in order; a
  waiting request honours its context; `WithQueueLimit` bounds how many
  wait. Select-before-operate holds the slot for both requests so that the
  OPERATE carries the next sequence number.
- **Response routing**: the session goroutine decodes each fragment. A
  response goes to the waiting transaction, which checks sequence numbers
  and FIR, confirms fragments that ask for it, and collects them until FIN.
  An unsolicited response is confirmed at once (with the UNS bit) and,
  unless it repeats the previous one, delivered.
- **Delivery**: every fragment with measurements goes to the `Handler` on
  the client's dispatcher goroutine, in arrival order, and so do state
  changes to the state handler. Handlers may take their time and may
  issue requests: responses are routed on the session goroutine, never
  through the dispatcher.
- **Automatic tasks** run one at a time on a task goroutine: the reactions
  to internal indications (clear the restart bit, integrity poll, time
  synchronization, event poll) and the periodic polls of `WithPoll`. A
  task already queued is not queued twice.
- **Retries** wrap a whole request: only those that are safe to repeat,
  only for timeouts and transport failures, while the caller's context
  lives. Each request is reported to `RequestMetrics` once, with its retries.

## Server

`server.Server` accepts connections and wraps each in a channel. Sessions
are created when a frame from an allowed master arrives, or at once when
exactly one master is configured, so that the null unsolicited response
can be sent before the master speaks.

The state of a master lives in its **association**, keyed by the master's
link address and kept across connections: its event buffer, internal
indications, select-before-operate state, the unsolicited state and its
open files. One goroutine owns all of it:

```text
 session goroutine ──► post(fragment) ─┐
 attach / detach   ──► post(f)        ─┤──► association goroutine ──► handler calls
 database updates  ──► wake           ─┤     (requests in order,         (one at a time
 timers            ──────────────────── ┘      confirm and select         per master)
                                              timeouts, unsolicited)
```

- **Requests and attachment share one FIFO**, so a fragment is never
  handled before the session it came on is attached.
- **The database** is shared by all associations and safe for concurrent
  use. An update that produces an event appends it to every association's
  buffer; a `Batch` hands all its events over at once, so they are reported
  in the same response.
- **Event buffers** keep events in the order they occurred, which is the
  order they are reported in across point types. Events written into a
  response are *selected*; they are removed when the master confirms the
  fragment that carried them, and selected again later when it does not.
  When a type's limit is reached the oldest event is discarded and
  EVENT_BUFFER_OVERFLOW set until a confirmation frees room.
- **Responses** are planned as logical headers, then packed into fragments
  no larger than the master's maximum, splitting headers at object
  boundaries and repeating the CTO in each fragment with relative-time
  events. Every fragment but the last, and every fragment with events, asks
  for confirmation; the next one is sent when it arrives.
- **Unsolicited responses**: a null response after a connection, repeated
  until confirmed; then events of the enabled classes, collected for the
  hold time, as one fragment, repeated with the same sequence number until
  confirmed or given up, after which they wait for the retry delay. They
  never overlap a solicited response that waits for its confirmation.
- **Controls**: SELECT stores the encoded object headers, the sequence
  number and the time; OPERATE must repeat the headers, carry the next
  sequence number and arrive within the select timeout, or every control
  gets NO_SELECT. The handler decides each control's status.

## Secure Authentication

On an outstation with `WithSecureAuthentication`, a critical request is
held and answered with an authentication challenge (g120v1). The master
computes the MAC over the challenge as it was sent and the critical request
as it was sent, and replies (g120v2) with the next sequence number. The
outstation verifies the MAC, then executes the held request and answers it
with the reply's sequence number. A select stores that number, so that the
OPERATE that follows, itself challenged, matches it. A wrong MAC is
answered with an authentication error (g120v7) and nothing is executed.

## Testing strategy

| Level | What | Where |
|-------|------|-------|
| Codec | known vectors, round trips of every variation under every qualifier, error paths, fuzzing with stable re-encoding | `link`, `transport`, `app` |
| Link procedures | secondary state machine frame by frame, confirmed data with retries and NACK, keep-alive, noisy and duplicating lines | `internal/channel` |
| Outstation conformance | a scripted master sending exact requests: malformed requests and their IIN, repeated requests, broadcast, confirm timeouts, unsolicited retries and hold, select timeout, pattern control | `server` |
| Master | timeouts and retries against a silent peer, queue limit, TLS, polls, state and logging | `client` |
| End to end | master against outstation for every function; concurrency, many masters, reconnects, rapid open and close, cancellation | `e2e` |
| Interop | both roles against stepfunc dnp3, opendnp3 and DSC Systems go-dnp3 | `interop` (build tag) |
