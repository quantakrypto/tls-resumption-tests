#!/usr/bin/env bash
# Does a server issue a session ticket on its own, or only once a request arrives?
#
# One instrument, one panel, one flag different. probe.py already carries --request none, so
# this experiment adds no new measurement code: the two runs differ in exactly one argument,
# which is what makes the comparison worth anything.
#
# The runs go back to back rather than in parallel, because the panel is CDN-fronted and two
# simultaneous runs would land on different edge nodes. Sequential runs a minute apart share
# an edge far more often than concurrent ones do.
#
# Volume: two probe.py runs, so four connections per host at most, 56 for the panel, about
# three minutes in total. Same scope as probe.py itself, which is to say no credential is ever
# sent and a ticket is never offered to a host that did not issue it.
set -euo pipefail
cd "$(dirname "$0")"

PY=${PYTHON:-python3}
PROBE=../probe.py

echo "== selftest =="
../selftest.sh >/dev/null
echo "instrument passed its self-test"

echo
echo "== run 1 of 2: silent, no application data =="
"$PY" "$PROBE" --request none --out-dir . --panel ../panel.txt
mv results.json silent-results.json
mv results.md   silent-results.md

echo
echo "== run 2 of 2: one HEAD per connection =="
"$PY" "$PROBE" --request head --out-dir . --panel ../panel.txt
mv results.json head-results.json
mv results.md   head-results.md

echo
echo "== comparison =="
"$PY" compare.py
