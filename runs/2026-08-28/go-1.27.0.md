# Go crypto/tls: expiry and trust-anchor membership

```
Go go1.27.0, darwin/arm64

A. CLIENT CERTIFICATE EXPIRY
  1. valid client certificate, first connection        full handshake  ACCEPTED
  2. valid client certificate, resumed (baseline)      RESUMED         ACCEPTED
     waiting 12s for the client certificate to expire...
  3. EXPIRED client certificate, resumed               full handshake  REJECTED (remote error: tls: expired certificate)
  4. EXPIRED client certificate, full handshake (control) full handshake  REJECTED (remote error: tls: expired certificate)

B. TRUST ANCHOR REMOVED FROM ClientCAs
  1. root present, first connection                    full handshake  ACCEPTED
  2. root present, resumed (baseline)                  RESUMED         ACCEPTED
  3. root REMOVED, resumed                             full handshake  REJECTED (remote error: tls: unknown certificate authority)
  4. root REMOVED, full handshake (control)            full handshake  REJECTED (remote error: tls: unknown certificate authority)
```
