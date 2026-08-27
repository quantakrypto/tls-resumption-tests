#!/bin/bash
# Offline self-test. Nothing leaves the machine.
#
# It exists because the interesting measurement in probe.py is a negative-capable one: the
# harness has to be able to say "this host did not resume". A parser that never manages to report
# a resumption would say that about every host in the panel, and the run would look like a
# finding. So before probe.py is pointed at anything public, it is pointed at local
# `openssl s_server` instances whose behaviour is known.
#
# Three phases, each a control on the instrument rather than on the subject:
#
#   1. a server that issues tickets and resumes   -> the harness must see BOTH
#   2. a server that issues no ticket at all      -> the harness must refuse to call that a
#                                                    refusal to resume
#   3. a closed port                              -> the harness must record the failure and
#                                                    carry on rather than abort the run
#   4. a session offered at the wrong host        -> the scope guard must refuse it, in both
#                                                    normal and `python -O` mode
#
# Phase 2 is the one that matters most. It is the same rule the other four experiments apply:
# a negative result must be distinguishable from a test that never posed the question.
set -u
cd "$(dirname "$0")"

OPENSSL="${OPENSSL:-openssl}"
PORT_A="${SELFTEST_PORT:-14433}"
PORT_B=$((PORT_A + 1))
PORT_CLOSED=$((PORT_A + 2))
DIR="selftest-out"

rm -rf "$DIR"; mkdir -p "$DIR"
SRV_A=0; SRV_B=0
trap 'kill "$SRV_A" "$SRV_B" 2>/dev/null; wait "$SRV_A" "$SRV_B" 2>/dev/null; true' EXIT

echo "=== generating a throwaway certificate for localhost (valid for one day) ==="
"$OPENSSL" req -x509 -newkey rsa:2048 -nodes -days 1 \
  -keyout "$DIR/server.key" -out "$DIR/server.pem" \
  -subj "/CN=localhost/O=public-endpoints selftest" \
  -addext "subjectAltName=DNS:localhost" 2>/dev/null \
  || { echo "FAIL: could not make a certificate"; exit 1; }

echo "=== starting two local s_server instances ==="
# A: ordinary TLS 1.3. Issues tickets, resumes.
"$OPENSSL" s_server -cert "$DIR/server.pem" -key "$DIR/server.key" \
  -accept "$PORT_A" -www -tls1_3 > "$DIR/server-a.log" 2>&1 &
SRV_A=$!
# B: TLS 1.3 with ticket issuance switched off. TLS 1.3 has no session-identifier resumption, so
# this server cannot resume and cannot be blamed for not resuming.
"$OPENSSL" s_server -cert "$DIR/server.pem" -key "$DIR/server.key" \
  -accept "$PORT_B" -www -tls1_3 -num_tickets 0 > "$DIR/server-b.log" 2>&1 &
SRV_B=$!
sleep 1
kill -0 "$SRV_A" 2>/dev/null || { echo "FAIL: s_server A did not start, see $DIR/server-a.log"; exit 1; }
kill -0 "$SRV_B" 2>/dev/null || { echo "FAIL: s_server B did not start, see $DIR/server-b.log"; exit 1; }

run_probe() {  # run_probe <port> <subdir> <comment>
  mkdir -p "$DIR/$2"
  printf 'localhost   %s\n' "$3" > "$DIR/$2/panel.txt"
  python3 probe.py \
    --panel "$DIR/$2/panel.txt" --out-dir "$DIR/$2" \
    --cafile "$DIR/server.pem" --port "$1" --request get \
    --pause 0 --resume-gap 0.2 --hold 1.5 --timeout 15
}

echo
echo "=== phase 1: a server that issues tickets and resumes ==="
run_probe "$PORT_A" phase1 "selftest: s_server that issues tickets and resumes" \
  || { echo "FAIL: probe.py exited non-zero on phase 1"; exit 1; }

echo
echo "=== phase 2: a server that issues no ticket ==="
run_probe "$PORT_B" phase2 "selftest: s_server with num_tickets 0, cannot resume" \
  || { echo "FAIL: probe.py exited non-zero on phase 2"; exit 1; }

echo
echo "=== phase 3: a closed port ==="
run_probe "$PORT_CLOSED" phase3 "selftest: nothing is listening here" \
  || { echo "FAIL: probe.py exited non-zero on phase 3, it should record and continue"; exit 1; }

echo
echo "=== phase 4: the scope guard, offline, in both interpreter modes ==="
# Run twice, the second time with -O, because an `assert` would silently vanish there and the
# guard would stop existing exactly where nobody would notice.
for FLAGS in "" "-O"; do
  python3 $FLAGS - <<'PY' || { echo "FAIL: scope guard did not hold"; exit 1; }
import os, sys, tempfile
sys.path.insert(0, os.getcwd())
from probe import check_session_provenance, CrossHostReplayRefused

mode = "with -O" if not __debug__ else "normally"
work = tempfile.mkdtemp()
sess, minted = os.path.join(work, "session.pem"), os.path.join(work, "minted-by")
open(sess, "w").write("not a real session")
open(minted, "w").write("open.example")

# Offering it back at its own host must be allowed.
check_session_provenance(sess, minted, "open.example")

# Offering it at any other host must be refused.
try:
    check_session_provenance(sess, minted, "protected.example")
except CrossHostReplayRefused:
    pass
else:
    print(f"  scope guard {mode}  FAILED: a cross-host replay was permitted")
    sys.exit(1)

# A session with no provenance record must also be refused, rather than offered on trust.
os.unlink(minted)
try:
    check_session_provenance(sess, minted, "open.example")
except CrossHostReplayRefused:
    pass
else:
    print(f"  scope guard {mode}  FAILED: a session of unknown origin was permitted")
    sys.exit(1)

print(f"  scope guard {mode}  ok")
PY
done

echo
echo "=== checking what it recorded ==="
python3 - "$DIR" <<'PY'
import json, sys

base = sys.argv[1]
load = lambda phase: json.load(open(f"{base}/{phase}/results.json"))["records"][0]

one, two, three = load("phase1"), load("phase2"), load("phase3")

hs1 = one.get("connection_1_full_handshake") or {}
chain = one.get("certificate_chain") or {}
leaf = chain.get("leaf") or {}
ticket = one.get("session_ticket") or {}
resume = one.get("connection_2_resumption") or {}
controls = one.get("controls") or {}

checks = [
    # Phase 1. Every field the public run reports has to be readable here first.
    ("1 host was measured",                 one.get("outcome") == "measured"),
    ("1 first handshake completed",         hs1.get("handshake_completed") is True),
    ("1 TLS version recorded",              (hs1.get("tls_version") or "").startswith("TLSv1.")),
    ("1 cipher recorded",                   bool(hs1.get("cipher"))),
    ("1 key exchange group recorded",       bool((hs1.get("key_exchange_group") or {}).get("name"))),
    ("1 group classified",                  (hs1.get("key_exchange_group") or {}).get("class") is not None),
    ("1 first handshake verified ok",       hs1.get("verify_return_code") == 0),
    ("1 peername verified on full hs",      hs1.get("verified_peername") == "localhost"),
    ("1 chain counted",                     chain.get("count") == 1),
    ("1 chain DER bytes counted",           isinstance(chain.get("der_bytes_total"), int) and chain["der_bytes_total"] > 500),
    ("1 leaf issuer CN read",               leaf.get("issuer_cn") == "localhost"),
    ("1 leaf key type read",                leaf.get("key_type") == "RSA"),
    ("1 leaf key size read",                leaf.get("key_bits") == 2048),
    ("1 leaf signature algorithm read",     bool(leaf.get("signature_algorithm"))),
    ("1 leaf notBefore read",               bool(leaf.get("not_before"))),
    ("1 leaf notAfter read",                bool(leaf.get("not_after"))),
    ("1 ticket issuance detected",          ticket.get("issued") is True),
    ("1 ticket route recorded",             ticket.get("observed_via") == "post_handshake_newsessionticket"),
    ("1 ticket lifetime hint read",         isinstance(ticket.get("lifetime_hint_seconds"), int)),
    ("1 RESUMPTION DETECTED",               resume.get("resumed") is True),
    ("1 resumption mechanism named",        resume.get("mechanism") == "tls13_psk"),
    ("1 verify recorded on resumption",     resume.get("verify_return_code") == 0),
    # The observable the write-up turns on: OpenSSL prints `Verified peername` when it has
    # checked a name against a certificate the peer just sent, and does not print it on a
    # resumed connection. If this ever became non-null on resumption, the claim made about it in
    # results.md would be wrong and would need withdrawing.
    ("1 no peername reverify on resume",    resume.get("verified_peername") is None),
    ("1 result is readable",                controls.get("negative_result_is_readable") is True),

    # Phase 2. THE CONTROL. A server that never issued a ticket must not be recorded as having
    # refused to resume. If this check fails, every "did not resume" in the public results is
    # unreadable and the run must be discarded.
    ("2 host was measured",                 two.get("outcome") == "measured"),
    ("2 handshake still completed",         (two.get("connection_1_full_handshake") or {}).get("handshake_completed") is True),
    ("2 no ticket recorded",                (two.get("session_ticket") or {}).get("issued") is False),
    ("2 no ticket reason given",            bool((two.get("session_ticket") or {}).get("unavailable_reason"))),
    ("2 resumption NOT attempted",          (two.get("connection_2_resumption") or {}).get("attempted") is False),
    ("2 resumed is null, not false",        (two.get("connection_2_resumption") or {}).get("resumed") is None),
    ("2 NOT READ AS A REFUSAL",             (two.get("controls") or {}).get("negative_result_is_readable") is False),

    # Phase 3. A dead endpoint is a recorded outcome, not a crash and not a silent gap.
    ("3 failure recorded, not measured",    three.get("outcome") != "measured"),
    ("3 failure has a named outcome",       three.get("outcome") in
                                            ("handshake_failure", "timeout", "dns_failure",
                                             "openssl_spawn_failure", "harness_error")),
    ("3 failure carries a reason",          bool(three.get("error"))),
    ("3 no invented measurements",          three.get("certificate_chain") is None
                                            and three.get("session_ticket") is None),
]

width = max(len(name) for name, _ in checks)
failed = 0
for name, ok in checks:
    print(f"  {name.ljust(width)}  {'ok' if ok else 'FAILED'}")
    failed += not ok

print()
if failed:
    print(f"SELFTEST FAILED: {failed} of {len(checks)} checks did not hold.")
    print("probe.py must not be run against the public panel until this passes.")
    sys.exit(1)
print(f"SELFTEST PASSED: {len(checks)} checks, plus the phase 4 scope guard above.")
print("The harness can see a ticket, can see a resumption, refuses to call a ticketless host a")
print("refusal, records a dead endpoint without aborting, and will not replay across hosts.")
PY
STATUS=$?

echo
echo "artefacts in $DIR/. Nothing there is committed."
exit $STATUS
