#!/bin/bash
# Mirror of the section 2 measurement, on the side the paper's threat model says matters:
# a SERVER accepting a resumed session that carries an EXPIRED CLIENT certificate.
set -eu
cd "$(dirname "$0")"
CLIENT_SECONDS=${CLIENT_SECONDS:-45}
rm -f *.pem *.key *.srl *.csr 2>/dev/null || true

now=$(date -u +%Y%m%d%H%M%SZ)
end=$(date -u -v+${CLIENT_SECONDS}S +%Y%m%d%H%M%SZ 2>/dev/null || date -u -d "+${CLIENT_SECONDS} seconds" +%Y%m%d%H%M%SZ)

# CA
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem -days 2 \
  -subj "/CN=Anchor Age Test CA" -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null

# server certificate: long lived, so it is never the variable under test
openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr -subj "/CN=localhost" 2>/dev/null
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out server.pem -days 2 \
  -extfile <(printf "basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost\n") 2>/dev/null

# client certificate: valid for CLIENT_SECONDS only. THIS is the variable.
openssl req -newkey rsa:2048 -nodes -keyout client.key -out client.csr -subj "/CN=test-client" 2>/dev/null
openssl x509 -req -in client.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out client.pem \
  -not_before "$now" -not_after "$end" \
  -extfile <(printf "basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n") 2>/dev/null

echo "client certificate validity:"
openssl x509 -in client.pem -noout -dates | sed 's/^/    /'
