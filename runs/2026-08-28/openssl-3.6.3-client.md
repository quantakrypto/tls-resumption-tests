# OpenSSL client: resuming past SERVER certificate expiry

```
OpenSSL 3.6.3 9 Jun 2026 (Library: OpenSSL 3.6.3 9 Jun 2026)

server up, certificate valid for 40s

--- 1. certificate VALID: full handshake, hold open to capture the ticket ---
    New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
    Verify return code: 0 (ok)
    session saved (    1169 bytes)

--- waiting for the certificate to expire ---
    certificate is now EXPIRED

--- 2. certificate EXPIRED, resuming the saved session ---
    Reused, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
    Verify return code: 0 (ok)

--- 3. control: certificate EXPIRED, no saved session ---
    New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
    Verify return code: 10 (certificate has expired)

=== server-side log: what actually happened on the wire ===
1	   2.8	FULL    	cert_valid=True
2	  51.0	RESUMED 	cert_valid=False
3	  54.0	FULL    	cert_valid=False
```
