# OpenSSL server: resumed session carrying an EXPIRED client certificate

```
OpenSSL 3.6.3 9 Jun 2026 (Library: OpenSSL 3.6.3 9 Jun 2026)

client certificate validity:
    notBefore=Aug 27 23:00:21 2026 GMT
    notAfter=Aug 27 23:01:06 2026 GMT
=== 1. client certificate VALID, full handshake ===
    client: New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
    client: Verify return code: 0 (ok)
    session saved (    2835 bytes)

=== waiting for the CLIENT certificate to expire ===
    client certificate is now EXPIRED
    openssl verify: CN=test-client
    openssl verify: error 10 at 0 depth lookup: certificate has expired
    openssl verify: error client.pem: verification failed

=== 2. client certificate EXPIRED, RESUMING the saved session ===
    client: Reused, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
    client: Verify return code: 0 (ok)
    SERVER ACCEPTED THE CONNECTION

=== 3. client certificate EXPIRED, full handshake (CONTROL) ===
    client: New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
    client: Verify return code: 0 (ok)
    SERVER REJECTED

=== server log ===
    verify depth is 1, must return a certificate
    depth=1 CN=Anchor Age Test CA
    verify return:1
    depth=0 CN=test-client
    verify return:1
    depth=1 CN=Anchor Age Test CA
    verify return:1
    depth=0 CN=test-client
    verify error:num=10:certificate has expired
    notAfter=Aug 27 23:01:06 2026 GMT
    402CB0EE01000000:error:0A000086:SSL routines:tls_process_client_certificate:certificate verify failed:ssl/statem/statem_srvr.c:3929:
```
