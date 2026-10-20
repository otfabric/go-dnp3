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
| Latest release | Yes |
| Older releases | Best effort |

## Security Considerations

### DNP3 Without Protection

Plain DNP3 carries no authentication and no encryption: anyone who can reach an outstation on port 20000 can read it and send it controls, and anyone on the path can read or alter the traffic. The controls operate physical equipment.

- **Keep plain DNP3 traffic on isolated, trusted networks**; never expose port 20000 to the Internet
- **Use TLS across untrusted networks** (`client.WithTLS`, `server.WithTLS`), or put a VPN or secured gateway in front of the outstation
- **Restrict the masters** an outstation answers with `server.WithMasters`. A link address is not an authentication: it only keeps a misconfigured master out

### TLS

- `server.WithTLS` and `client.WithTLS` take a standard `*tls.Config`; the library does not weaken or override it. Set `MinVersion` to TLS 1.2 or later
- For mutual authentication set `ClientAuth: tls.RequireAndVerifyClientCert` and `ClientCAs` on the server and `Certificates` on the client. Without it a TLS outstation still accepts controls from any master
- Keep private keys out of source control and give key files restrictive permissions (`chmod 600`)

### Secure Authentication v5

`WithSecureAuthentication` on both ends makes the outstation execute critical requests (controls, writes, restarts, freezes, file operations, ...) only after the master proved knowledge of the control direction session key with an HMAC over the challenge and the request.

- **Use an update key.** With `secauth.User.UpdateKey` (16 or 32 random octets) the master generates fresh session keys on every connection and at the key change interval, and sends them wrapped with the update key (AES key wrap, RFC 3394); the outstation drops them when the connection ends. The pre-shared session key mode (`secauth.User.Key` without an update key) never changes its key and is meant for testing
- **Update keys are configured out of band.** The update key change procedures (symmetric and asymmetric) and user management are not implemented, nor is AES-GMAC: keep update keys out of source control and rotate them by reconfiguring both ends
- **Aggressive mode** (`client.WithAggressiveMode`) saves the challenge round trip: the MAC is bound to the last challenge and the outstation checks that the challenge sequence numbers follow each other, so a request cannot be replayed. It still trusts one challenge for several requests; enable it only where the latency matters
- **A held critical request expires.** `SecureAuth.ReplyTimeout` (10 s by default) bounds how long the outstation waits for the reply to its challenge
- **Watch the security statistics.** The outstation counts authentication failures, refused key changes, reply timeouts and more per master (g121, readable by any master); `StatisticsThreshold` and `StatisticsClass` make them events (g122) a SCADA system can alarm on
- **Only the control direction is authenticated.** Responses and unsolicited data from the outstation are not authenticated; use TLS to protect them
- **Non-critical requests (READ) are not challenged.** They disclose data without authentication; use TLS where that matters
- Secure Authentication is verified against DSC go-dnp3 in both roles (dnp3-interop v0.2.0, contract 1.1); aggressive mode only between go-dnp3's ends, as no reference implements it (see [INTEROPERABILITY.md](INTEROPERABILITY.md))

### Resource Limits

The library bounds what a peer can make it hold:

- Frames are at most 292 octets; fragments are reassembled up to `WithMaxFragment` (2048 by default)
- Every count and range in a request is checked against the octets that carry it before anything is allocated for it; the fuzz targets check this
- Received fragments wait in bounded queues; a peer that floods them loses fragments, not memory
- Event buffers have a limit per point type (`server.WithEventLimits`)
- The outstation limits connections (`server.WithMaxConnections`, 16 by default), controls per request (`WithMaxControls`) and open files per master (16)
- Writes are bounded by a deadline on streams that support one (TCP, TLS, UDP: 10 s), so a peer that stops reading closes its connection instead of blocking the station

### File Transfer

- `server.FSFileServer` is read-only and serves only what its `fs.FS` contains; file names are cleaned and must be valid `fs.FS` paths, so `..` cannot leave it
- A writable `FileServer` is the application's code: validate names, sizes and the authentication key, and never map names onto the file system unchecked
- `AUTHENTICATE_FILE` credentials travel in clear text unless the link is protected with TLS

### Dependencies

- `go-dnp3` has **zero third-party dependencies**: only the Go standard library
- `make vuln` runs `govulncheck`; CI runs it on every push
