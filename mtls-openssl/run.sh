#!/bin/bash
# Does a TLS 1.3 SERVER accept a resumed session carrying an EXPIRED CLIENT certificate?
# Three connections, one variable: the client certificate's validity.
#   1. client cert VALID,   full handshake   -> expect accept  (baseline)
#   2. client cert EXPIRED, RESUMED          -> the question
#   3. client cert EXPIRED, full handshake   -> expect REJECT  (control)
set -u
cd "$(dirname "$0")"
PORT=8444
rm -f sess.pem server.out client*.out

openssl s_server -accept $PORT -tls1_3 -cert server.pem -key server.key \
  -CAfile ca.pem -Verify 1 -verify_return_error -naccept 3 -quiet > server.out 2>&1 &
SRV=$!
sleep 2
hold() { printf "hello\n"; sleep 4; }

echo "=== 1. client certificate VALID, full handshake ==="
hold | openssl s_client -connect localhost:$PORT -tls1_3 -CAfile ca.pem \
  -cert client.pem -key client.key -sess_out sess.pem > client1.out 2>&1
grep -E "^New,|^Reused|Verify return code" client1.out | head -2 | sed 's/^/    client: /'
[ -s sess.pem ] && echo "    session saved ($(wc -c < sess.pem) bytes)" || echo "    NO SESSION SAVED"

echo
echo "=== waiting for the CLIENT certificate to expire ==="
while openssl x509 -in client.pem -noout -checkend 0 >/dev/null 2>&1; do sleep 2; done
echo "    client certificate is now EXPIRED"
openssl verify -CAfile ca.pem client.pem 2>&1 | sed 's/^/    openssl verify: /'

echo
echo "=== 2. client certificate EXPIRED, RESUMING the saved session ==="
hold | openssl s_client -connect localhost:$PORT -tls1_3 -CAfile ca.pem \
  -cert client.pem -key client.key -sess_in sess.pem > client2.out 2>&1
grep -E "^New,|^Reused|Verify return code" client2.out | head -2 | sed 's/^/    client: /'
grep -qiE "alert|error|fail" client2.out && echo "    SERVER REJECTED" || echo "    SERVER ACCEPTED THE CONNECTION"

echo
echo "=== 3. client certificate EXPIRED, full handshake (CONTROL) ==="
hold | openssl s_client -connect localhost:$PORT -tls1_3 -CAfile ca.pem \
  -cert client.pem -key client.key > client3.out 2>&1
grep -E "^New,|^Reused|Verify return code" client3.out | head -2 | sed 's/^/    client: /'
grep -qiE "alert|error|fail" client3.out && echo "    SERVER REJECTED" || echo "    SERVER ACCEPTED THE CONNECTION"

kill $SRV 2>/dev/null
echo
echo "=== server log ==="
sed 's/^/    /' server.out | head -30
