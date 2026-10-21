# IED conformance procedures (dnp3c)

`make conformance` runs the DNP Users Group's *DNP3 IED Certification
Procedure* against the go-dnp3 outstation, using
[dnp3c](https://github.com/stepfunc/dnp3c), Step Function I/O's independent
implementation of it. It runs revision 3.1 rev 1 at subset levels 2 and 3,
and revision 2.7 at level 2. CI runs the same on every push
([conformance.yml](../../../.github/workflows/conformance.yml)). The results
show how this outstation answers the procedures. They are not a
certification: only the DNP Users Group certifies devices.

```bash
make conformance                                      # needs Go and Docker
internal/cmd/conformance/run.sh 3.1r1:3 8.11 8.14.2m  # one run, some procedures (after make conformance-image)
```

dnp3c's reports are written to
`bin/conformance/results/<revision>/L<level>/report.html`.

## How it fits together

- **This command** is the device under test: a go-dnp3 outstation (address
  1024, TCP port 20000) with a fixed database. It also has a control port
  (20099) for the steps a tester would otherwise do by hand: restarting it,
  changing its configuration, changing inputs, and checking that an output
  operated.
- **[device.ini](device.ini)** is its Device Profile, in dnp3c's terms.
- **dnp3c runs in a container**: dnp3-interop's `dnp3-interop-dnp3c` image.
  It holds dnp3c, an integration plugin that forwards each such step to the
  control port, and a runner that runs every procedure on its own. dnp3-interop's
  [docs/CONFORMANCE.md](https://github.com/otfabric/dnp3-interop/blob/main/docs/CONFORMANCE.md)
  specifies the control protocol.
- **`make conformance-image`** builds that image from dnp3-interop's source at
  `CONFORMANCE_COMMIT` (Makefile). It is not published.

### The Device Profile

- **Points:** indices 0 to 3 of every point type the subset level has, plus
  binary inputs 4 to 6 in classes 2, 2 and 3, for Assign Class.
- **Double-bit inputs only for 2.7:** dnp3c puts their objects at level 4 in
  3.1r1.
- **Frozen counter events only at level 3**, where their objects start.
- **Event variations g22v1 and g32v1, and analog output status g40v2:**
  go-dnp3's defaults (g22v5, g32v3, g40v1) are outside levels 1 and 2.
- **Unsolicited responses are off at startup.** The procedures turn them on
  where they need them.
- **Response fragments of 512 octets.**
- **Time synchronization:** NEED_TIME every 10 s, and the time counts as
  unsynchronized after 20 s without a synchronization.
- **Configuration changes** (link confirmation, unsolicited responses,
  master address) take effect at the next restart, as offline
  configuration does. dnp3c restarts the device after each one.

## Licences

This command is MIT-licensed, like the rest of go-dnp3. dnp3c and
dnp3-interop's plugin and runner are licensed under the GNU General Public
License v3.0 only. They are not in this repository and are not
redistributed: the image build fetches dnp3c from Maven Central, and the
image stays on the machine that built it. The outstation and the runner only
talk over TCP.
