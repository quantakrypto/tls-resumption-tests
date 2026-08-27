# nginx cross-vhost client-auth scope (CVE-2025-23419)

```
nginx version: nginx/1.31.4
OpenSSL 3.6.3 9 Jun 2026 (Library: OpenSSL 3.6.3 9 Jun 2026)


=== 1. CONTROL: protected.test, full handshake, NO client certificate ===
    refused, as it must be. Verify return code: 0 (ok)

=== 2. mint a ticket at open.test (no client certificate requested there) ===
    open host served content
    ticket saved (1775 bytes)

=== 3. THE TEST: replay that ticket at protected.test, still no client certificate ===
    session reused by the TLS layer: no
    RESULT: not vulnerable. 400 No required SSL certificate

=== 4. CONTROL: replay the SAME ticket back at open.test ===
    ticket RESUMED at its own host, so it was valid and offerable
    => step 3's full handshake is nginx declining it, which is the fix working
```
