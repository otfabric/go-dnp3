#!/bin/sh
# SPDX-License-Identifier: MIT
#
# Runs the DNP Users Group's DNP3 IED Certification Procedure, as Step
# Function I/O's dnp3c implements it, against the conformance outstation of
# this directory, with dnp3-interop's dnp3c runner image
# (DNP3_INTEROP_DNP3C_IMAGE; make conformance-image builds it). dnp3c's
# reports go to bin/conformance/results/<revision>/L<level>/report.html.
#
#   make conformance                                      3.1r1 at levels 2 and 3, and 2.7
#   internal/cmd/conformance/run.sh 3.1r1:3               one revision and level
#   internal/cmd/conformance/run.sh 3.1r1:2 8.11 8.14.2m  only these procedures or sections
#
# Exits non-zero when a procedure fails or is excluded.
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../../.." && pwd)"
out="$root/bin/conformance"
image="${DNP3_INTEROP_DNP3C_IMAGE:?set DNP3_INTEROP_DNP3C_IMAGE, or run make conformance}"

runs="${1:-3.1r1:2 3.1r1:3 2.7:2}"
[ $# -gt 0 ] && shift

mkdir -p "$out"
(cd "$root" && go build -o "$out/outstation" ./internal/cmd/conformance)

# On Linux the runner shares the host's network and reaches the outstation on
# the loopback; Docker Desktop has no host network, and reaches it as
# host.docker.internal.
if [ "$(uname -s)" = Linux ]; then
	network="--network=host"
	host=127.0.0.1
else
	network="--add-host=host.docker.internal:host-gateway"
	host=host.docker.internal
fi

status=0
for run in $runs; do
	rev=${run%%:*}
	level=${run##*:}
	ini=device-$rev-L$level.ini
	sed -e "s/^outstation.subset.level = .*/outstation.subset.level = $level/" \
		-e "s/^tcp.device.address = .*/tcp.device.address = $host/" \
		"$here/device.ini" > "$out/$ini"
	if [ "$level" -ge 3 ]; then
		# frozen counter events are level 3 objects
		sed '/^supports.frozenCounterChangeEvents = false$/d' "$out/$ini" > "$out/$ini.tmp" && mv "$out/$ini.tmp" "$out/$ini"
	fi
	double_bit=false
	if [ "$rev" = "2.7" ]; then
		# 2.7 has double-bit inputs at level 2 (3.1r1 at level 4)
		double_bit=true
		sed '/^supports.doubleBitInput = false$/d' "$out/$ini" > "$out/$ini.tmp" && mv "$out/$ini.tmp" "$out/$ini"
		cat >> "$out/$ini" <<-EOT
			supports.doubleBitInput = true
			doubleBitInput.eventsClass = 1
			doubleBitInput.defaultEventVariation = 2
			event.buffer.maxDoubleBitInputEvents = 100
		EOT
	fi
	rm -rf "$out/results/$rev/L$level"
	log="$out/outstation-$rev-L$level.log"
	"$out/outstation" -level "$level" -double-bit="$double_bit" > "$log" 2>&1 &
	outstation=$!
	# wait until it listens
	i=0
	until grep -q "control on" "$log" 2>/dev/null; do
		i=$((i + 1))
		[ $i -gt 100 ] && { echo "the conformance outstation did not start" >&2; kill $outstation; exit 1; }
		sleep 0.1
	done
	echo "== dnp3c $rev, subset level $level"
	docker run --rm "$network" --user "$(id -u):$(id -g)" -v "$out:/work" "$image" \
		"$rev" "$ini" "$host:20099" "$@" > "$out/dnp3c-$rev-L$level.log" 2>&1 || status=1
	kill $outstation 2>/dev/null || true
	wait $outstation 2>/dev/null || true
	grep -E '^(FAIL|EXCLUDED|WARN) |procedures,' "$out/dnp3c-$rev-L$level.log" || true
done
exit $status
