# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in `go-dnp3`, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, please email **security@otfabric.io**, or open a private advisory on GitHub (the [Security](https://github.com/otfabric/go-dnp3/security) tab → **Advisories** → **Report a vulnerability**), with:

- A description of the vulnerability
- Steps to reproduce the issue, ideally a minimal program or test
- The affected version(s)
- Any potential impact you've identified

We will acknowledge your report within 48 hours and aim to provide a fix or mitigation within 7 days for critical issues.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.15.x | Yes |
| 1.14.x | Yes |
| 1.4.x – 1.13.x | No: upgrade to 1.15.x |
| 1.0.x – 1.3.x | No: upgrade to 1.15.x. These versions crash the outstation on a malformed READ of g70v5 that any master able to reach it can send (fixed in v1.4.0) |
| 0.x | No |

## Security Considerations

### DNP3 Without Protection

Plain DNP3 carries no authentication and no encryption: anyone who can reach an outstation on port 20000 can read it and send it controls, and anyone on the path can read or alter the traffic. The controls operate physical equipment.

- **Keep plain DNP3 traffic on isolated, trusted networks**; never expose port 20000 to the Internet
- **Use TLS across untrusted networks** (`client.WithTLS`, `server.WithTLS`), or put a VPN or secured gateway in front of the outstation
- **Restrict the masters** an outstation answers with `server.WithMasters`. A link address is not an authentication: it only keeps a misconfigured master out

### Restricting the addresses a station connects to

The client (`client.WithDialer`, `client.UDPWithDialer`) and the outstation's dial-out (`server.WithDialer` for `DialAndServe`) open their connections through a dialer the application can supply.

- **Put an address allowlist in the dialer**, for example in `net.Dialer.Control`, which sees the resolved IP address right before the connection is made, and return a sentinel error for a refused address: it reaches the caller wrapped in `dnp3.ErrConnectFailed`, and `errors.Is` finds it
- **Do not check the host name before dialling**: the name can resolve to another address when the dialer resolves it again (DNS rebinding), so a check of the name leaves that gap
- `client.UDP`, `client.UDPFrom` and a `StreamOpener` of `WithStream` do not use `client.WithDialer`: use `client.UDPWithDialer` or apply the allowlist in the opener

### TLS

- `server.WithTLS` and `client.WithTLS` take a standard `*tls.Config`; the library does not weaken or override it. Set `MinVersion` to TLS 1.2 or later
- For mutual authentication set `ClientAuth: tls.RequireAndVerifyClientCert` and `ClientCAs` on the server and `Certificates` on the client. Without it a TLS outstation still accepts controls from any master
- Keep private keys out of source control and give key files restrictive permissions (`chmod 600`)

### Secure Authentication v5

`WithSecureAuthentication` on both ends makes the outstation execute critical requests (controls, writes, restarts, freezes, file operations, ...) only after the master proved knowledge of the control direction session key with an HMAC over the challenge and the request.

- **Use an update key.** With `secauth.User.UpdateKey` (16 or 32 random octets) the master generates fresh session keys on every connection and at the key change interval, and sends them wrapped with the update key (AES key wrap, RFC 3394); the outstation drops them when the connection ends. The pre-shared session key mode (`secauth.User.Key` without an update key) never changes its key and is meant for testing. A device whose manual speaks of a "pre-shared key", one per device, means the update key: configure it as `UpdateKey`, with the user number the device uses (1, the default user, unless it says otherwise; 0 is taken as 1)
- **The outstation chooses the MAC algorithm** of a challenge's reply. The master accepts every algorithm it computes except the obsolete HMAC-SHA-1/4 and, over TCP and UDP, the 8-octet truncations (clause 7.6.1.1); `client.WithChallengeMACs` narrows the list, for example to the HMAC-SHA-256 variants where HMAC-SHA-1 is not allowed. The MACs of a key status and of the confirmation of a key change follow the same rule
- **A key change the key change count asks for stays due** until one succeeds: a failed one is tried again
- **HMAC-SHA-1 can be turned off.** Every device must implement it and provide a means to disable it by configuration (clause 7.6.1.1.1), which is why `secauth` imports `crypto/sha1`. The outstation uses it only when `secauth.User.MAC` names it (the default is HMAC-SHA-256 truncated to 16); `client.WithChallengeMACs` without the SHA-1 variants makes the master refuse it
- **Update keys are configured out of band.** The update key change procedures (symmetric and asymmetric) and user management are not implemented, nor is AES-GMAC: keep update keys out of source control and rotate them by reconfiguring both ends
- **Aggressive mode** (`client.WithAggressiveMode`) saves the challenge round trip: the MAC is bound to the last challenge and the outstation checks that the challenge sequence numbers follow each other, so a request cannot be replayed. It still trusts one challenge for several requests; enable it only where the latency matters. An outstation turns it off with `SecureAuth.NoAggressiveMode`. The MAC follows IEEE 1815-2012 Table A-9; aggressive mode needs both ends at this release or later
- **A critical broadcast is carried out only in aggressive mode.** A broadcast cannot be challenged: with secure authentication the outstation discards a critical one without a valid aggressive mode MAC, counts it as discarded and answers nothing. A valid one is carried out also when it arrives on another session than the master's current one (its datagram socket while it is connected over TCP); a refused one from such a session is discarded without counting as an authentication failure
- **Secure authentication messages are not broadcast.** AUTHENTICATE_REQ and AUTHENTICATE_REQ_NO_ACK sent to a broadcast address are discarded and counted, never answered, and change no authentication state
- **A held critical request expires.** `SecureAuth.ReplyTimeout` (2 s by default) bounds how long the outstation waits for the reply to its challenge; meanwhile it discards other requests
- **Session keys expire.** The master changes them at the interval (15 min), after 1000 authentication messages, after an outstation restart and after a refused authentication; the outstation stops accepting them after 30 min or 2000 messages without a change, and after repeated authentication failures or reply timeouts
- **Error messages are rate-limited.** The outstation stops answering failed authentications with error messages past Max Error Messages Sent (3) until the next key change, and closes a TCP connection that keeps failing after the keys were invalidated three times
- **The key status is authenticated.** The master checks the key status MAC with the last monitoring key before it changes the keys, and counts a status that fails as an authentication failure (possible attack, logged)
- **Watch the security statistics.** The outstation counts authentication failures, refused key changes, reply timeouts and more per master (g121, readable by any master); `StatisticsThreshold` and `StatisticsClass` make them events (g122) a SCADA system can alarm on
- **Only the control direction is authenticated.** Responses and unsolicited data from the outstation are not authenticated; use TLS to protect them
- **Non-critical requests (READ) are not challenged.** They disclose data without authentication; use TLS where that matters
- Secure Authentication is verified against DSC go-dnp3 and cB-Sigma dnp3 in both roles (dnp3-interop v0.12.1; file authentication since contract 1.3); aggressive mode only between go-dnp3's ends, as no reference implements it (see [INTEROPERABILITY.md](INTEROPERABILITY.md))

### Static analysis

Gosec and Opengrep scans run on a maintainer's machine before each release, with `cd ../engineering && make sast REPO=go-dnp3`, from a checkout of otfabric/engineering beside this one ([ADR-0011](https://github.com/otfabric/engineering/blob/main/docs/adr/0011-shared-sast.md)), never in a GitHub workflow, so that a public CI log does not publish a finding before it is fixed. Gosec findings are fixed in code: no `//nolint` or `#nosec`. The one accepted finding is G505, the `crypto/sha1` import above, which IEEE 1815-2012 7.6.1.1.1 requires; it is recorded in the organisation's private triage, not in this repository. Jitter of retries and redials draws from `crypto/rand`. A clean scan is not a proof that no weakness is left.

### Resource Limits

The library bounds what a peer can make it hold:

- Frames are at most 292 octets; fragments are reassembled up to `WithMaxFragment` (2048 by default)
- Every count and range in a request is checked against the octets that carry it before anything is allocated for it; the allocation-budget tests (`budget_test.go` in `link`, `transport`, `app` and `internal/channel`) and the fuzz targets check this
- Received fragments wait in bounded queues; a peer that floods them loses fragments, not memory
- Event buffers have a limit per point type (`server.WithEventLimits`)
- The outstation limits connections (`server.WithMaxConnections`, 16 by default, counted from accept, during a TLS handshake too), associations (`server.WithMaxAssociations`: one per master link address, the number of `WithMasters` by default, else 16; a frame of another master address beyond them is dropped before anything is kept for it, and an association ends when the server is closed), controls per request (`WithMaxControls`, each point of a pattern control block counted), open files per master (16) and scheduled FREEZE_AT_TIME requests (`server.MaxScheduledFreezes`, 16, counted across all associations; a periodic interval below 100 ms is served as 100 ms)
- A READ plans at most four times the points of the database, plus 1024: each header is charged with the points it selects, headers that are not of points (device attributes g0, file blocks g70v5, IIN bits g80, statistics g121) with the objects they produce, file blocks before the file is read, and a request beyond that is answered with IIN2.2. Event headers are bounded by the event buffer limits: each event is reported at most once per response. Splitting a response into fragments costs time in proportion to its objects
- `server.Close` ends the TLS handshakes in progress
- The master holds at most 64 fragments or 4 MiB (each fragment counted as at least 48 octets per decoded object) for a `Handler` that falls behind: beyond them it does not take unsolicited responses (the outstation repeats them) and every automatic task waits (time synchronization, restart handling, key changes, polls). The bound is exceeded by at most one unsolicited fragment and one automatic response that began below it
- A directory listing (`client.ListDirectory`) is collected up to 16 MiB, each decoded entry counted with 48 octets; a longer one is refused with `dnp3.ErrProtocol`
- `client.ReadFile` refuses file data beyond the size the outstation announced in its OPEN_FILE answer
- A response is collected up to `client.WithMaxResponse` octets over all its fragments (16 MiB by default), each fragment counted as the larger of its octets and 48 octets per decoded object; a longer one is abandoned with `dnp3.ErrProtocol`
- Writes are bounded by a deadline on streams that support one (TCP, TLS, UDP: 10 s), so a peer that stops reading closes its connection instead of blocking the station

### Application code

Application code the library calls (handlers, the file server, metrics, the logger, streams, listeners, dialers, stream openers, `tls.Config` callbacks, the function of `Database.Batch`, the readers and writers of file transfers) that does not return normally is recovered where the library calls it and logged with its stack (`callback did not return normally`, or the error entries of the handlers in [OBSERVABILITY.md](OBSERVABILITY.md)). The request, connection attempt or transfer in hand fails or goes unanswered; the other associations and channels, and the process, go on. The logged `value` is what the code ended with: keep secrets out of it.

### File Transfer

- `server.FSFileServer` is read-only and serves only what its `fs.FS` contains; file names are cleaned and must be valid `fs.FS` paths, so `..` cannot leave it
- `FSFileServer` follows symbolic links when its `fs.FS` does: `os.DirFS` follows them, also out of its directory. Serve a directory with the `FS` method of an `os.Root` (`os.OpenRoot`), which does not follow links out of it
- A `File` the `FileServer` returns with a refused OPEN_FILE is closed. Open and delete compare cleaned file names, and DELETE_FILE and OPEN_FILE of the same file in different associations exclude each other (FILE_LOCKED)
- A writable `FileServer` is the application's code: validate names, sizes and the authentication key, and never map names onto the file system unchecked
- `AUTHENTICATE_FILE` credentials travel in clear text unless the link is protected with TLS

### Dependencies

- `go-dnp3` has **zero third-party dependencies**: only the Go standard library
- `make vuln` runs `govulncheck`; CI runs it on every pull request
