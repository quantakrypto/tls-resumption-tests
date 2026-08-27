# HAProxy cross-frontend resumption

```
HAProxy version 3.4.3-80ea565fd 2026/07/29 - https://haproxy.org/
OpenSSL 3.6.3 9 Jun 2026 (Library: OpenSSL 3.6.3 9 Jun 2026)

HAProxy under test: HAProxy version 3.4.3-80ea565fd 2026/07/29 - https://haproxy.org/

=== 1. CONTROL: protected frontend, full handshake, NO client certificate ===
    refused, as it must be

=== 2. mint a ticket on the OPEN frontend (no client certificate requested) ===
    open frontend served
    ticket saved (1710 bytes)

=== 3. THE TEST: replay that ticket on the PROTECTED frontend ===
    session reused by the TLS layer: no
    RESULT: not served.

=== 4. CONTROL: replay the SAME ticket back on the OPEN frontend ===
    ticket RESUMED at its own frontend, so it was valid and offerable
```
