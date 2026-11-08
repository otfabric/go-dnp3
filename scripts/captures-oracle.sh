#!/bin/sh
# Regenerates testdata/captures/tshark/: Wireshark's DNP3 dissector's view of
# every committed capture, one tab-separated line per frame with DNP3 in it.
# internal/capture's TestTshark compares go-dnp3's decoding with it. Needs
# tshark; the files are committed, so the tests run without it.
set -eu
cd "$(dirname "$0")/../testdata/captures"
command -v tshark >/dev/null || { echo "tshark not found" >&2; exit 1; }
version=$(tshark -v | head -n1)
grep '\.pcap$' SHA256SUMS | while read -r _ local; do
	out="tshark/${local%.pcap}.tsv"
	mkdir -p "$(dirname "$out")"
	{
		printf '# %s\n' "$version"
		printf '# frame\tctl\tsrc\tdst\tlen\ttr.ctl\tal.ctl\tal.func\tal.iin\tal.obj\tobjq.prefix\tobjq.range\n'
		tshark -r "$local" -d tcp.port==20001,dnp3 -Y dnp3 -T fields -E occurrence=a -E aggregator='|' \
			-e frame.number -e dnp3.ctl -e dnp3.src -e dnp3.dst -e dnp3.len -e dnp3.tr.ctl \
			-e dnp3.al.ctl -e dnp3.al.func -e dnp3.al.iin -e dnp3.al.obj \
			-e dnp3.al.objq.prefix -e dnp3.al.objq.range 2>/dev/null
	} >"$out"
done
