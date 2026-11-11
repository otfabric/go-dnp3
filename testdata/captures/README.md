# Recorded DNP3 traffic

Network captures of DNP3 over TCP recorded by others: software masters and
outstations in test beds, a DNP3 conformance test runner against the
opendnp3 3.0 outstation, the Zeek DNP3 analyzer's test traces and an attack
data set. go-dnp3's tests read every frame of every file with its own link,
transport and application codecs, encode what they decode back to the
recorded octets, compare the decoding with two independent decoders
(Wireshark's DNP3 dissector and the conformance runner's own log), run the
master against the recorded outstations' replies and send the recorded
masters' requests to the outstation, comparing its answers with the recorded
ones.

**None of these recordings is established as traffic of a physical DNP3
device.** They are software-generated or of unknown origin (evidence classes
C and D below). They support statements about go-dnp3 and the recorded
software, not about any RTU or IED. See [Hardware](#hardware).

[manifest.json](manifest.json) is the machine-readable inventory (source,
revision, original name and path, URL, SHA256, size, recording date,
evidence class, peers, operations, limitations; for the conformance
captures the procedure, the runner's verdict and its log; the source files
examined but not committed, with why); [coverage.json](coverage.json) the
per-file report of what the codecs find, rewritten by `make
captures-report`; [tshark/](tshark) Wireshark's decoding of every file,
rewritten by `make captures-oracle` (Wireshark 4.6.9).

## Evidence classes

| Class | Meaning | Files |
|---|---|---|
| A | verified physical-device traffic: the device identified by its own answers in the recording | none |
| B | credibly documented physical-device traffic, not verified from the traffic | none |
| C | independent recorded traffic, hardware origin unknown | 16 |
| D | simulated or software test-bed traffic | 167 |
| E | standards-derived examples or generated fixtures | none here (the unit tests have them) |

## Sources and terms

Every file is committed byte-identical to its source under the name of the
scheme below; [SHA256SUMS](SHA256SUMS) covers them all and the conformance
logs (`make captures-verify`, CI job `Captures`). Every file is under 50 MB
(the largest is 2.7 MB, 8.4 MB in all), so all of them run in `make test`,
offline; there is no extended corpus. The terms are what each source
states.

| Directory | Source | Revision | Files | Class | Terms stated by the source |
|---|---|---|---|---|---|
| `iti-dnp3/` | [ITI/ICS-Security-Tools](https://github.com/ITI/ICS-Security-Tools), `pcaps/dnp3/` | `bcb93ee1cdf395a457cc08f639cf29aab5975f01` | 29 | D (27), C (2: `test-data-part1/2`, recorded 2004 and 2007) | CC-BY-4.0 (repository licence). Its README: recorded "using various DNP3 software packages" to write tests for a firewall parser; the packages are not named |
| `iti-dnp3-conformance/` | the same, `pcaps/dnp3/opendnp3-3/conformance/` | the same | 140 captures with the runner's `log.html` | D | CC-BY-4.0. A DNP3 conformance runner (master side) against the opendnp3 3.0 outstation (named by the directory and the commit "Bring in the opendnp3 3.0 conformance captures", 2020-05-28), on loopback |
| `iti-zeek-dnp3/` | the same, `pcaps/bro/dnp3/` | the same | 12 | C | CC-BY-4.0. The DNP3 traces of the Bro (Zeek) test suite; no provenance stated |
| `igbe/` | [igbe/DNP3-Dataset-Plus-SnortRules](https://github.com/igbe/DNP3-Dataset-Plus-SnortRules) | `a5c48f8b07ca93a3b8979975a6e3a8db2f55f66a` | 1 | C | no licence; the README requires citing Igbe, Darwish and Saadawi, "Deterministic Dendritic Cell Algorithm Application to Smart-Grid Cyber Attack Detection", IEEE CSCloud 2017, which we do here |
| `unknown-origin/` | not known: a capture handed to the maintainer, its source and author unknown | none | 1 | C | not known; committed byte-identical at the maintainer's decision with the origin recorded as unknown, and removed if its owner objects. `TestManifest` requires such a source to have no URL or revision and its files to be class C or D |

[nblair2/go-dnp3](https://github.com/nblair2/go-dnp3) (`56a515110af9a82191841c0e90363b5d1c2d79d5`)
lists 167 of the ITI `pcaps/dnp3` files in `test/corpus.txt` at ITI revision
`9b826091`; their SHA256 match the files here (the directories did not change
between the two ITI revisions).

Not committed (manifest.json `examined`): the 19 conformance dumps that hold
no packet (the runner skipped or failed the procedure before sending), and
automayt/ICS-pcap's DNP3 files, which are Git LFS pointers, not captures.

Privacy: the captures hold private addresses, the public addresses of a
university test bed (the Zeek traces), file names and contents of test files
("This is a test file", an XML configuration), and secure authentication
exchanges whose update and session keys are not in the recordings. No
password or key is in them.

## Hardware

No recording here identifies a DNP3 device by make, model or firmware. One
hint, not evidence: in `iti-zeek-dnp3/unknown_unknown_link-only.pcap` the
outstation's MAC address 00:50:c2:4f:94:64 lies in the IEEE block
00-50-C2-4F-9 assigned to RTDS Technologies Inc., which suggests an RTDS
simulator's network card; neither the source nor the traffic says so, and
the file stays class C. A search for public captures of identified physical
outstations (SEL, GE, ABB, Schneider and others) found none: the vendors'
tools save captures of the user's own devices, and the public DNP3 data sets
found (this ITI collection, the igbe set, the DNP3 Intrusion Detection
Dataset on Zenodo record 7348493) are test beds of software. Statements about
real devices need a capture of an identified one.

A second hint, also not evidence: in
`unknown-origin/unknown_unknown_poll-select-operate.pcap` the outstation's
MAC address 00:30:a7:1c:08:a3 lies in the OUI 00-30-A7 assigned to Schweitzer
Engineering Laboratories (SEL). The capture says nothing else about the
device, its origin is unknown, and the file stays class C.

## Names

`<client-or-peer>_<device>_<operation>.<ext>`, lower case, words joined by
hyphens; the extension is the original's (`.pcap`). `unknown` stands for a
side the source does not identify; `conformance-runner` is the runner, and
`opendnp3-3` the outstation the source names. The conformance captures are
named by their procedure (`8-14-2-10` is procedure 8.14.2.10); their logs
have the same name with `.log.html`.

| File | Original name | Class | Recorded | Functions (Wireshark) |
|---|---|---|---|---|
| `iti-dnp3/unknown_unknown_assign-class.pcap` | `assign_class.pcap` | D | 2015-03-27 | ASSIGN_CLASS |
| `iti-dnp3/unknown_unknown_auth-change-session-keys.pcap` | `auth_change_session_keys.pcap` | D | 2015-03-25 | AUTHENTICATE_REQ/RESP (g120v4, v5, v6) |
| `iti-dnp3/unknown_unknown_auth-control-challenge-response.pcap` | `auth_control_challenge_response.pcap` | D | 2015-03-25 | DIRECT_OPERATE challenged (g120v1, v2) |
| `iti-dnp3/unknown_unknown_cold-restart-and-response.pcap` | `cold_restart_and_response.pcap` | D | 2015-01-29 | COLD_RESTART |
| `iti-dnp3/unknown_unknown_dataset-exchange.pcap` | `dataset_exchange.pcap` | D | 2015-08-19 | READ g0v213, g0v215, g85, g86 |
| `iti-dnp3/unknown_unknown_direct-operate-analog-output.pcap` | `direct_operate_analog_output.pcap` | D | 2015-04-20 | DIRECT_OPERATE g41 (request only) |
| `iti-dnp3/unknown_unknown_direct-operate-crob-malform-but-good-crc.pcap` | `direct_operate_crob_malform_but_good_crc.pcap` | D | 2015-04-17 | DIRECT_OPERATE, malformed g12v1 |
| `iti-dnp3/unknown_unknown_direct-operate-no-ack-crob.pcap` | `direct_operate_no_ack_crob.pcap` | D | 2015-04-21 | DIRECT_OPERATE_NR |
| `iti-dnp3/unknown_unknown_direct-operate-and-response.pcap` | `directoperate_and_response.pcap` | D | 2015-01-29 | DIRECT_OPERATE |
| `iti-dnp3/unknown_unknown_disable-unsolicited-and-response.pcap` | `disable_unsolcited_and_response.pcap` | D | 2015-01-28 | DISABLE_UNSOLICITED |
| `iti-dnp3/unknown_unknown_enable-unsolicited-and-response.pcap` | `enable_unsolicited_and_response.pcap` | D | 2015-01-28 | ENABLE_UNSOLICITED |
| `iti-dnp3/unknown_unknown_file-delete.pcap` | `file_delete.pcap` | D | 2015-03-27 | DELETE_FILE |
| `iti-dnp3/unknown_unknown_file-list-directory.pcap` | `file_list_directory.pcap` | D | 2015-03-27 | OPEN_FILE, READ g70v5, CLOSE_FILE |
| `iti-dnp3/unknown_unknown_file-read.pcap` | `file_read.pcap` | D | 2015-03-27 | OPEN_FILE, READ g70v5, CLOSE_FILE |
| `iti-dnp3/unknown_unknown_file-write.pcap` | `file_write.pcap` | D | 2015-03-27 | OPEN_FILE, WRITE g70v5, CLOSE_FILE |
| `iti-dnp3/unknown_unknown_full-exchange.pcap` | `full_exchange.pcap` | D | 2015-01-28 | startup, integrity poll, unsolicited |
| `iti-dnp3/unknown_unknown_immediate-freeze.pcap` | `immediate_freeze.pcap` | D | 2015-03-27 | IMMED_FREEZE |
| `iti-dnp3/unknown_unknown_lan-time-sync.pcap` | `lan_time_sync.pcap` | D | 2015-03-25 | RECORD_CURRENT_TIME, WRITE g50v3 |
| `iti-dnp3/unknown_unknown_operate-aggressive-mode.pcap` | `operate_aggressive_mode.pcap` | D | 2015-03-25 | DIRECT_OPERATE in aggressive mode (g120v3, v9) |
| `iti-dnp3/unknown_unknown_read-and-response.pcap` | `read_and_response.pcap` | D | 2015-01-28 | READ |
| `iti-dnp3/unknown_unknown_select-operate-and-responses.pcap` | `select_operate_and_responses.pcap` | D | 2015-01-29 | SELECT, OPERATE |
| `iti-dnp3/unknown_unknown_serial-time-sync.pcap` | `serial_time_sync.pcap` | D | 2015-03-25 | DELAY_MEASURE, WRITE g50v1 |
| `iti-dnp3/unknown_unknown_test-data-part1.pcap` | `dnp3_test_data_part1.pcap` | C | 2004-10-11 | many, with damaged frames |
| `iti-dnp3/unknown_unknown_test-data-part2.pcap` | `dnp3_test_data_part2.pcap` | C | 2007-05-03 | READ, SELECT |
| `iti-dnp3/unknown_unknown_unsolicited-response-and-confirm.pcap` | `unsolcited_response_and_confirm.pcap` | D | 2015-01-28 | UNSOLICITED_RESPONSE, CONFIRM |
| `iti-dnp3/unknown_unknown_warm-restart-and-response.pcap` | `warm_restart_and_response.pcap` | D | 2015-01-29 | WARM_RESTART |
| `iti-dnp3/unknown_unknown_write-binary-output.pcap` | `write_binary_output.pcap` | D | 2015-04-23 | WRITE g10 (request only) |
| `iti-dnp3/unknown_unknown_write-iin-and-response.pcap` | `write_iin_and_response.pcap` | D | 2015-01-28 | WRITE g80v1 |
| `iti-dnp3/unknown_unknown_write-vto-empty-string.pcap` | `write_vto_empty_string.pcap` | D | 2015-04-24 | WRITE 285 × g112v0 (request only) |
| `iti-dnp3-conformance/conformance-runner_opendnp3-3_<procedure>.pcap` (140) | `opendnp3-3/conformance/<procedure>/dump.pcap` | D | 2020-04-10 | link procedures (6.x), transport (7.2), application (8.x) |
| `iti-zeek-dnp3/unknown_unknown_test-data-merged.pcap` | `dnp3.pcap` | C | 2004-10-11 | test-data part 1 and 2 in one file |
| `iti-zeek-dnp3/unknown_unknown_del-measure.pcap` | `dnp3_del_measure.pcap` | C | 2011-12-21 | DELAY_MEASURE |
| `iti-zeek-dnp3/unknown_unknown_en-spon.pcap` | `dnp3_en_spon.pcap` | C | 2011-12-26 | ENABLE_UNSOLICITED |
| `iti-zeek-dnp3/unknown_unknown_file-del.pcap` | `dnp3_file_del.pcap` | C | 2011-12-28 | DELETE_FILE |
| `iti-zeek-dnp3/unknown_unknown_file-read.pcap` | `dnp3_file_read.pcap` | C | 2011-12-28 | file read with time sync in between |
| `iti-zeek-dnp3/unknown_unknown_file-write.pcap` | `dnp3_file_write.pcap` | C | 2011-12-28 | file write |
| `iti-zeek-dnp3/unknown_unknown_link-only.pcap` | `dnp3_link_only.pcap` | C | 2013-04-12 | class polls (see [Hardware](#hardware)) |
| `iti-zeek-dnp3/unknown_unknown_read.pcap` | `dnp3_read.pcap` | C | 2011-12-19 | READ |
| `iti-zeek-dnp3/unknown_unknown_read-p20001.pcap` | `dnp3_read_p20001.pcap` | C | 2011-12-19 | READ, outstation on port 20001 |
| `iti-zeek-dnp3/unknown_unknown_rec-time.pcap` | `dnp3_rec_time.pcap` | C | 2011-12-21 | RECORD_CURRENT_TIME |
| `iti-zeek-dnp3/unknown_unknown_select-operate.pcap` | `dnp3_select_operate.pcap` | C | 2011-12-21 | SELECT, OPERATE |
| `iti-zeek-dnp3/unknown_unknown_write.pcap` | `dnp3_write.pcap` | C | 2011-12-21 | WRITE |
| `igbe/unknown_unknown_ddca-smart-grid-attacks.pcap` | `dnp3dataset_capture.pcap` | C | 2017-02-13 | 26058 packets, 546 TCP connections with DNP3: polls, controls, injected cold restarts and other attacks |
| `unknown-origin/unknown_unknown_poll-select-operate.pcap` | `dnp3_example.pcap` | C | 2020-03-10 | 834 DNP3 packets (handshakes and pure ACKs filtered out): one connection with polls (g60v1–v4) and 4 g2v2 unsolicited responses the master does not confirm; ten connections of SELECT/OPERATE (134 SELECT, 133 OPERATE; nine of 14 pairs) (g12v1 TRIP and CLOSE pulses of 500 ms), the next SELECT sent before the previous answers (see Comparison rules) |

## What the tests do

| Test | Package | What |
|---|---|---|
| `TestManifest` | `internal/capture` | manifest, SHA256SUMS and files agree; names follow the scheme; no class A or B |
| `TestRoundTrip` | `internal/capture` | each of the 14524 decoded link frames and 13188 decoded fragments encodes back to the recorded octets |
| `TestTshark` | `internal/capture` | link header, transport header, application header, IIN and object headers (group, variation, qualifier) of every frame against Wireshark's dissector |
| `TestConformanceLog` | `internal/capture` | the octets the runner logged sending and receiving are the capture's reassembled streams; its link, transport and application decoding (1063 L, 1024 T and 968 A rows, 1206 object header rows and 4858 values) against go-dnp3's |
| `TestAnomalies`, `TestTransport`, `TestCoverage`, `TestFunctionsSeen` | `internal/capture` | every framing, transport and application error classified; no transport refusal; coverage.json up to date |
| `TestFuzzSeeds` | `internal/capture` | 382 fuzz seeds from the captures in `link`, `app`, `server` and `client` |
| `TestCaptureClientReplay` | `client` | 5908 recorded requests sent through `Client.Request` (or `Broadcast`), byte-identical to the recorded ones apart from the sequence number; the recorded responses (5899 fragments, 100960 measurements) accepted; 651 unsolicited responses reach the Handler and are confirmed |
| `TestCaptureClientReadFile`, `…ListDirectory`, `…WriteFile`, `…DeleteFile`, `…SelectOperate`, `…TimeSync`, `…DelayMeasure`, `…Restart` | `client` | the client's procedures against the recorded outstations, its requests compared with the recorded masters' |
| `TestCaptureServerReplay` | `server` | 5933 recorded requests sent to the outstation; whether answered, FIR and sequence, IIN2 error bits and control echoes compared |
| `TestCaptureServerLinkReplay` | `server` | the octets of masters that use the link layer (resets, link status, confirmed data, damaged frames) sent as captured; the outstation's link reactions compared |

Conversations are reassembled per TCP direction in sequence order
(retransmitted octets credited to the first frame, a gap starts a new run, a
SYN on a reused address pair starts a new connection); `link.Reader` reads
the runs one octet at a time, so that every frame maps to the capture frame
that completed it.

### Comparison rules

- **Sequence numbers are dynamic.** The client replay answers with the
  recorded fragment octets, the application sequence number replaced by the
  client's (the low four bits of the control octet), re-segmented and
  re-framed with the recorded addresses. The server replay sends the
  recorded request fragment in UNCONFIRMED_USER_DATA frames.
- **File request IDs, file creation times and g50 times** are dynamic in the
  procedure replays. The width of an index qualifier (0x17 against 0x28)
  and a g70v3 size of 0 ("unknown") sent by a recorded master are encoding
  choices and normalised.
- **IIN1, data values and variations** in the server replay depend on the
  recorded outstation's state and configuration and are not compared. Its
  database is built from what the recorded outstation reported; outputs it
  answered NOT_SUPPORTED for are left out.
- **Requests are paired with responses by sequence number.** A recorded
  master may send a request before the answer to the previous one (the
  unknown-origin SELECT/OPERATE connections send SELECT, OPERATE and the
  next SELECT, reusing sequence numbers 7 and 8): every request stays open
  until its response ends, and a first response fragment goes to the oldest
  open request with its sequence number. A secure authentication RESPONSE
  after a challenge answers the challenged request (IEEE 1815-2012 clause
  7), not the AUTHENTICATE_REQ that carries the same sequence number.

## Results

Production fix: a READ of g0v0 was answered with IIN2.2 by an outstation
without device attribute sets; group 0 has no variation 0, and procedure
8.6.3.2 of the DNP3 IED certification procedure verifies IIN2.1, as the
recorded opendnp3 outstation answers (`conformance-runner_opendnp3-3_8-6-3-2.pcap`
frame 4). Regression test: `server/capture_regression_test.go`.

Classified differences (the tests list each one by file and frame):

| Category | What |
|---|---|
| legitimate refusal | damaged frames in `test-data-*` and the 6.6.2.x procedures (invalid start octets, undefined function codes 5 and 10, a length octet of 5 with data after it, user data on link functions without it), a qualifier 0xED, a g12v1 header that announces more objects than follow, injected octets in the igbe attack data; Wireshark and the runner decode some of these frames, go-dnp3 refuses them as IEEE 1815-2012 clause 9.2 requires, and the outstation does not answer them (link replay) |
| oracle limitation | Wireshark lists no object headers of ASSIGN_CLASS |
| legitimate protocol variation | a READ of a point type with no points: the 2020 runner expects an empty response (8.13.2.3, 8.16.1.2.3, 8.21.2.2), go-dnp3 answers IIN2.1 as TB2016-001 and procedure 3.1r1 Table 11-1 require; a malformed STOP_APPL answered with IIN2.2 where the recorded outstation stayed silent; 285 g112v0 headers without objects (Wireshark stops after the first) |
| vendor/implementation-specific difference | recorded outstations without restarts or unsolicited responses (IIN2.0) where the replay outstation has them; IIN2.1 and IIN2.2 together for an undefined group 255 |
| unsupported feature or configuration | data sets (g85, g86, g0v213/215) are not served by the outstation; secure authentication exchanges need keys the recordings do not hold |
| timing not reproduced | OPERATE after the select timeout (8.2.1.2.4, 8.4.1.2.4); requests sent before the previous answer (8.11.2.5) |
| evidence incomplete | recordings of the master side only; secure authentication MACs cannot be checked without the keys |

Compared with nblair2/go-dnp3's scoreboard (`test/README.md`, an
independent decoder; 123 of its 167 files clean): the files it leaves
undecoded because of secure authentication, file transfer, data sets and
time-tagged events decode here, and Wireshark and the runner's log agree
with that decoding. Both refuse the malformed g12v1 and the damaged frames
of `test-data-*` and 6.6.2.x.

Third-party observation: the conformance runner's frames in 6.6.2.3 and
6.6.2.4 carry a length octet of 5 with a data block after it, so the
outstation discards them for their length, not for the destination address
or CRC the procedures are meant to test. The runner version is not stated
and the runner's current release was not checked.
