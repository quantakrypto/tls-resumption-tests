#!/bin/bash
# Certificates for the CVE-2025-23419 reproduction.
# ONE certificate covering BOTH virtual hosts, and ONE CA for client certificates.
# That is the CVE's precondition: the two server blocks are indistinguishable to the
# session id context, and differ only in ssl_verify_client.
set -eu
cd "$(dirname "$0")"
rm -f *.pem *.key *.csr *.srl 2>/dev/null || true

openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem -days 2 \
  -subj "/CN=Resumption Scope Test CA" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign" 2>/dev/null

# ONE server certificate, valid for both names. This is what makes the two vhosts share
# a session id context under nginx's 2014 fix (certificate hash), which is exactly the
# space CVE-2025-23419 lives in.
openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr \
  -subj "/CN=open.test" 2>/dev/null
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out server.pem -days 2 \
  -extfile <(printf "basicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:open.test,DNS:protected.test\n") 2>/dev/null

# A client certificate, used only to prove the protected vhost really does demand one.
openssl req -newkey rsa:2048 -nodes -keyout client.key -out client.csr -subj "/CN=a-client" 2>/dev/null
openssl x509 -req -in client.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out client.pem -days 2 \
  -extfile <(printf "basicConstraints=CA:FALSE\nextendedKeyUsage=clientAuth\n") 2>/dev/null

openssl rand 80 > ticket.key   # ONE ticket key shared by both server blocks
echo "server certificate covers:"
openssl x509 -in server.pem -noout -ext subjectAltName | sed 's/^/    /'
