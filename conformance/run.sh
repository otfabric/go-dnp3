#!/bin/sh
# SPDX-License-Identifier: MIT
#
# Runs the DNP Users Group's DNP3 IED Certification Procedure, as Step
# Function I/O's dnp3c implements it, against the go-dnp3 conformance
# outstation (dut), and writes dnp3c's report to results/<revision>/L<level>/.
#
#   conformance/run.sh                 3.1r1 at levels 2 and 3, and 2.7 (level 2)
#   conformance/run.sh 3.1r1:3         one revision and level
#   conformance/run.sh 3.1r1:2 8.11    only these procedures or sections
#
# Needs Go, Java 17 or newer and Maven; dnp3c comes from Maven Central. Exits
# non-zero when a procedure fails or is excluded.
set -eu
cd "$(dirname "$0")"

runs="${1:-3.1r1:2 3.1r1:3 2.7:2}"
[ $# -gt 0 ] && shift

mkdir -p build
go build -o build/dut ./dut
mvn -q -B -f plugin/pom.xml compile dependency:build-classpath -Dmdep.outputFile="$PWD/build/classpath.txt"
cp="plugin/target/classes:$(cat build/classpath.txt)"

status=0
for run in $runs; do
	rev=${run%%:*}
	level=${run##*:}
	ini=build/device-$rev-L$level.ini
	sed "s/^outstation.subset.level = .*/outstation.subset.level = $level/" device.ini > "$ini"
	if [ "$level" -ge 3 ]; then
		# frozen counter events are level 3 objects
		sed '/^supports.frozenCounterChangeEvents = false$/d' "$ini" > "$ini.tmp" && mv "$ini.tmp" "$ini"
	fi
	double_bit=false
	if [ "$rev" = "2.7" ]; then
		# 2.7 has double-bit inputs at level 2 (3.1r1 at level 4)
		double_bit=true
		sed '/^supports.doubleBitInput = false$/d' "$ini" > "$ini.tmp" && mv "$ini.tmp" "$ini"
		cat >> "$ini" <<-EOT
			supports.doubleBitInput = true
			doubleBitInput.eventsClass = 1
			doubleBitInput.defaultEventVariation = 2
			event.buffer.maxDoubleBitInputEvents = 100
		EOT
	fi
	rm -rf "results/$rev/L$level"
	build/dut -level "$level" -double-bit="$double_bit" > "build/dut-$rev-L$level.log" 2>&1 &
	dut=$!
	# wait until it listens
	i=0
	until grep -q "control on" "build/dut-$rev-L$level.log" 2>/dev/null; do
		i=$((i + 1))
		[ $i -gt 100 ] && { echo "the conformance outstation did not start" >&2; kill $dut; exit 1; }
		sleep 0.1
	done
	echo "== dnp3c $rev, subset level $level"
	java -cp "$cp" io.otfabric.conformance.Run "$rev" "$ini" 127.0.0.1:20099 "$@" > "build/dnp3c-$rev-L$level.log" 2>&1 || status=1
	kill $dut 2>/dev/null || true
	wait $dut 2>/dev/null || true
	grep -E '^(FAIL|EXCLUDED|WARN) |^report:|procedures,' "build/dnp3c-$rev-L$level.log" || true
done
exit $status
