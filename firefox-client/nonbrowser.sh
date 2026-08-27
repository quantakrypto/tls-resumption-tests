#!/bin/bash
# Do NON-BROWSER TLS clients resume past certificate expiry?
#
# This is the population the paper argues about: service meshes, mobile backends,
# IoT, mutual TLS. Testing only Firefox measured the population the paper itself
# calls the weaker case.
#
# NOTE: in TLS 1.3 the NewSessionTicket arrives AFTER the handshake, so the client
# must hold the connection open or no session is saved and there is nothing to resume.
set -u
cd "$(dirname "$0")"
LEAF=40
rm -f connections.log server.out sess.pem
LEAF_SECONDS=$LEAF RELOAD_EVERY=9999 ../../venv2/bin/python server.py > server.out 2>&1 &
SRV=$!
sleep 3
echo "server up, certificate valid for ${LEAF}s"

req() { printf "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"; sleep 3; }

echo
echo "--- 1. certificate VALID: full handshake, hold open to capture the ticket ---"
req | openssl s_client -connect localhost:8443 -servername localhost \
  -CAfile ca.pem -sess_out sess.pem 2>/dev/null \
  | grep -E "Verify return code|New, TLSv|Reused" | head -2 | sed 's/^/    /'
[ -s sess.pem ] && echo "    session saved ($(wc -c < sess.pem) bytes)" || echo "    NO SESSION SAVED"

echo
echo "--- waiting for the certificate to expire ---"
until [ $SECONDS -gt $((LEAF + 8)) ]; do sleep 3; done
openssl x509 -in leaf.pem -noout -checkend 0 >/dev/null 2>&1 \
  && echo "    WARNING: still valid" || echo "    certificate is now EXPIRED"

echo
echo "--- 2. certificate EXPIRED, resuming the saved session ---"
req | openssl s_client -connect localhost:8443 -servername localhost \
  -CAfile ca.pem -sess_in sess.pem 2>/dev/null \
  | grep -E "Verify return code|New, TLSv|Reused" | head -2 | sed 's/^/    /'

echo
echo "--- 3. control: certificate EXPIRED, no saved session ---"
req | openssl s_client -connect localhost:8443 -servername localhost \
  -CAfile ca.pem 2>/dev/null \
  | grep -E "Verify return code|New, TLSv|Reused" | head -2 | sed 's/^/    /'

echo
echo "=== server-side log: what actually happened on the wire ==="
cat connections.log
kill $SRV 2>/dev/null
