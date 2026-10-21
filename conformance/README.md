# IED conformance procedures (dnp3c)

This directory runs the DNP Users Group's *DNP3 IED Certification
Procedure* against the go-dnp3 outstation, using
[dnp3c](https://github.com/stepfunc/dnp3c), Step Function I/O's independent
implementation of it. CI runs revision 3.1 rev 1 at subset levels 2 and 3
and revision 2.7 at level 2 on every push
([conformance.yml](../.github/workflows/conformance.yml)). The results show
how this outstation answers the procedures. They are not a certification:
only the DNP Users Group certifies devices.

```bash
make conformance
```

The command needs Go, Java 17 or newer and Maven. It writes dnp3c's
reports to `conformance/results/<revision>/L<level>/report.html`. To run one
revision and level, or only some procedures or sections, use the script:

```bash
conformance/run.sh 3.1r1:3 8.11 8.14.2m
```

## How it fits together

- **[dut](dut)** is the device under test: a go-dnp3 outstation (address
  1024, TCP port 20000) with a fixed database. It also has a control port
  (20099) for the steps a tester would otherwise do by hand: restarting it,
  changing its configuration, changing inputs, and checking that an output
  operated. It is MIT-licensed, like go-dnp3.
- **[plugin](plugin)** is dnp3c's integration plugin. Each call is
  forwarded to the outstation's control port, and the outstation acts on it
  or checks what dnp3c read against what it holds. The plugin also has the
  runner, which runs every procedure on its own, so that one failure doesn't
  stop the run. The runner then writes the report.
- **[device.ini](device.ini)** is the outstation's Device Profile, in
  dnp3c's terms.

### The Device Profile

- **Points:** indices 0 to 3 of every point type the subset level has, plus
  binary inputs 4 to 6 in classes 2, 2 and 3, for Assign Class.
- **No double-bit inputs:** dnp3c puts their objects at level 4.
- **Frozen counter events only at level 3**, where their objects start.
- **Event variations g22v1 and g32v1, and analog output status g40v2:**
  go-dnp3's defaults (g22v5, g32v3, g40v1) are outside levels 1 and 2.
- **Unsolicited responses are off at startup.** The procedures turn them on
  where they need them.
- **Response fragments of 512 octets.**
- **Time synchronization:** NEED_TIME every 10 s.
- **Configuration changes** (link confirmation, unsolicited responses,
  master address) take effect at the next restart, as offline
  configuration does. dnp3c restarts the device after each one.

## Licences

dnp3c is licensed under the GNU General Public License v3.0 only. It is not
part of this repository and is not redistributed: the plugin's build
downloads version 0.2.0 from Maven Central.

The plugin runs in dnp3c's JVM and uses its API, so it is GPL-3.0-only too
([plugin/LICENSE](plugin/LICENSE)). The outstation runs as a separate process
and talks to the plugin over a socket. It is MIT-licensed, like the rest of
go-dnp3. `conformance` is a Go module of its own, so neither is part of the
`github.com/otfabric/go-dnp3` module.
