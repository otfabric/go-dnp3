# Examples

Runnable programs to start from. Each is one `main.go` that uses only the
public API.

The first six are self-contained: they start an outstation and a master in
one process, connected over TCP on loopback, so `go run` shows the whole
exchange and there is nothing to set up.

| Example | Shows | Run |
|---------|-------|-----|
| [quickstart](quickstart/main.go) | The smallest complete outstation and master: a database with three points, `Dial`, `IntegrityPoll` | `go run ./examples/quickstart` |
| [commands](commands/main.go) | Select-before-operate and direct operate of a CROB, a trip, a set-point, a no-ack control, a refusal as `*dnp3.CommandError`, and the outputs read back | `go run ./examples/commands` |
| [events](events/main.go) | Event classes, a batch reported in one unsolicited response, a deadband, the master's startup sequence | `go run ./examples/events` |
| [files](files/main.go) | File transfer: `FSFileServer` over an `fs.FS`; `ListDirectory`, `ReadFile`, `FileInfo` | `go run ./examples/files` |
| [secure](secure/main.go) | Secure Authentication v5: the session key change under an update key, challenged controls, and a master with the wrong update key refused | `go run ./examples/secure` |
| [observability](observability/main.go) | `slog` logging and metrics on both sides, a state handler, retries, reconnect and a periodic poll | `go run ./examples/observability` |

The last two are an outstation and a master as separate programs, for
trying the library against something else: another implementation, a
simulator, a device.

| Example | Shows | Run |
|---------|-------|-----|
| [server](server/main.go) | An outstation with binary and analog inputs, a counter with its frozen counter, a controllable breaker, periodic updates and unsolicited responses | `go run ./examples/server -addr :20000 -address 10` |
| [client](client/main.go) | Connect, the startup sequence, time synchronization on demand, optionally latch a binary output, then print everything the outstation reports | `go run ./examples/client -addr 127.0.0.1:20000 -operate 0` |

Both take `-debug` to log every frame and fragment.

`make build` compiles all of them to `bin/example-<name>`; `make examples`
runs the self-contained ones, which is also how CI keeps them working.

## Where to go from each

- An outstation of your own: start from **quickstart**, add a control
  handler as in **commands**, report changes as in **events**.
- A master of your own: **client** for the shape of the program,
  **observability** for the options a long-running one needs.
