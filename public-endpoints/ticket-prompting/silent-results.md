# Public endpoints: what the certificate handshake does

Run on 2026-08-28T01:14:28Z, from OpenSSL 3.6.3 9 Jun 2026 (Library: OpenSSL 3.6.3 9 Jun 2026), against the 14 hosts in `panel.txt` (sha256 `f05931e024c211d5`). Two connections per host: one to mint a session ticket, one to offer it back to the same address and the same SNI.

This is a measurement of ordinary client behaviour against public infrastructure. It reads certificates and observes whether a resumption offer is accepted. It sends no credential, and it never offers a ticket to a host other than the one that issued it. See [README.md](README.md) for why that second restriction is a boundary and not a preference.

## Summary

- 14 of 14 hosts measured; 0 could not be.
- 8 issued a session ticket.
- 7 resumed a connection that offered that ticket back.
- 11 negotiated a post-quantum hybrid key exchange group.

| host | ip | version | group | PQ hybrid | chain | chain bytes | ticket | lifetime (s) | resumed | via | verify |
|---|---|---|---|---|---|---|---|---|---|---|---|
| aws.amazon.com | 143.204.238.22 | TLSv1.3 | X25519MLKEM768 | yes | 3 | 3916 | yes | 77838 | yes | tls13_psk | 0 |
| docs.aws.amazon.com | 13.35.58.2 | TLSv1.3 | X25519MLKEM768 | yes | 3 | 3778 | yes | 77829 | yes | tls13_psk | 0 |
| cloud.google.com | 142.251.168.100 | TLSv1.3 | X25519MLKEM768 | yes | 3 | 4812 | no | - | - | - | - |
| azure.microsoft.com | 23.212.194.150 | TLSv1.3 | X25519MLKEM768 | yes | 3 | 5785 | yes | 83100 | yes | tls13_psk | 0 |
| learn.microsoft.com | 23.212.193.214 | TLSv1.3 | X25519MLKEM768 | yes | 3 | 3725 | yes | 83100 | yes | tls13_psk | 0 |
| www.cloudflare.com | 104.16.123.96 | TLSv1.3 | X25519MLKEM768 | yes | 3 | 2493 | no | - | - | - | - |
| developers.cloudflare.com | 104.16.2.189 | TLSv1.3 | X25519MLKEM768 | yes | 3 | 2515 | no | - | - | - | - |
| www.fastly.com | 151.101.1.57 | TLSv1.3 | X25519MLKEM768 | yes | 2 | 2530 | yes | 86400 | yes | tls13_psk | 0 |
| docs.fastly.com | 151.101.1.91 | TLSv1.3 | X25519MLKEM768 | yes | 2 | 2544 | yes | 86400 | yes | tls13_psk | 0 |
| ietf.org | 104.16.44.99 | TLSv1.3 | X25519MLKEM768 | yes | 3 | 2465 | no | - | - | - | - |
| letsencrypt.org | 35.157.26.135 | TLSv1.3 | - | - | 4 | 3576 | yes | 604800 | yes | tls13_psk | 0 |
| github.com | 140.82.121.3 | TLSv1.3 | - | - | 3 | 2719 | yes | 7200 | no | - | 0 |
| google.com | 172.253.157.100 | TLSv1.3 | X25519MLKEM768 | yes | 3 | 4812 | no | - | - | - | - |
| mozilla.org | 35.190.14.201 | TLSv1.3 | - | - | 3 | 3954 | no | - | - | - | - |

A row reading ticket `no`, resumed `yes` is not a contradiction. TLS 1.2 can resume on a session identifier with no ticket in the exchange at all, and the `via` column says which mechanism carried it. In TLS 1.3 there is only one, a PSK, and it comes from a ticket.

## Reading the resumption column

A blank or `no` in the resumed column is only a statement about the server if a ticket was issued and offered back. Where it was not, the question was never posed and the row says nothing about that host's willingness to resume. The hosts in that position in this run:

- `cloud.google.com`: no session was saved, so no ticket was offered. A host that issues no ticket cannot be said to have refused to resume.
- `www.cloudflare.com`: no session was saved, so no ticket was offered. A host that issues no ticket cannot be said to have refused to resume.
- `developers.cloudflare.com`: no session was saved, so no ticket was offered. A host that issues no ticket cannot be said to have refused to resume.
- `ietf.org`: no session was saved, so no ticket was offered. A host that issues no ticket cannot be said to have refused to resume.
- `google.com`: no session was saved, so no ticket was offered. A host that issues no ticket cannot be said to have refused to resume.
- `mozilla.org`: no session was saved, so no ticket was offered. A host that issues no ticket cannot be said to have refused to resume.

## Per host

### aws.amazon.com

AWS. Amazon's own product site, served from CloudFront.

```
address pinned for both connections : 143.204.238.22
all addresses resolved              : 143.204.238.22, 143.204.238.36, 143.204.238.49, 143.204.238.96
negotiated                          : TLSv1.3, TLS_AES_128_GCM_SHA256, group X25519MLKEM768 (pq_hybrid)
chain                               : 3 certificates, 3916 DER bytes
leaf issuer CN                      : Amazon RSA 2048 M04
leaf key                            : RSA 2048 bit
leaf signature algorithm            : sha256WithRSAEncryption
leaf validity                       : 2025-11-06 00:00:00Z .. 2026-10-17 23:59:59Z
first connection verify             : 0 (ok)
session ticket                      : yes, seen via post_handshake_newsessionticket, lifetime hint 77838
resumed on second connection        : yes, via tls13_psk
verify on the resumed connection    : 0 (ok)
peername reverified on resumption   : not reported
```

### docs.aws.amazon.com

AWS. Amazon's own documentation site, served from CloudFront. Second AWS point of presence, so a divergence between the two is visible rather than hidden.

```
address pinned for both connections : 13.35.58.2
all addresses resolved              : 13.35.58.2, 13.35.58.67, 13.35.58.82, 13.35.58.99
negotiated                          : TLSv1.3, TLS_AES_128_GCM_SHA256, group X25519MLKEM768 (pq_hybrid)
chain                               : 3 certificates, 3778 DER bytes
leaf issuer CN                      : Amazon RSA 2048 M01
leaf key                            : RSA 2048 bit
leaf signature algorithm            : sha256WithRSAEncryption
leaf validity                       : 2025-11-09 00:00:00Z .. 2026-12-08 23:59:59Z
first connection verify             : 0 (ok)
session ticket                      : yes, seen via post_handshake_newsessionticket, lifetime hint 77829
resumed on second connection        : yes, via tls13_psk
verify on the resumed connection    : 0 (ok)
peername reverified on resumption   : not reported
```

### cloud.google.com

Google Cloud. Google's own product and documentation site, served from the Google Front End.

```
address pinned for both connections : 142.251.168.100
all addresses resolved              : 142.251.168.100, 142.251.168.101, 142.251.168.102, 142.251.168.113, 142.251.168.138, 142.251.168.139
negotiated                          : TLSv1.3, TLS_AES_256_GCM_SHA384, group X25519MLKEM768 (pq_hybrid)
chain                               : 3 certificates, 4812 DER bytes
leaf issuer CN                      : WR2
leaf key                            : EC 256 bit P-256
leaf signature algorithm            : sha256WithRSAEncryption
leaf validity                       : 2026-08-10 08:37:35Z .. 2026-11-02 08:37:34Z
first connection verify             : 0 (ok)
session ticket                      : no, seen via nothing, lifetime hint -
resumed on second connection        : -
verify on the resumed connection    : - ()
peername reverified on resumption   : not reported
```

### azure.microsoft.com

Azure. Microsoft's own product site, served from Azure Front Door.

```
address pinned for both connections : 23.212.194.150
all addresses resolved              : 23.212.194.150
negotiated                          : TLSv1.3, TLS_AES_256_GCM_SHA384, group X25519MLKEM768 (pq_hybrid)
chain                               : 3 certificates, 5785 DER bytes
leaf issuer CN                      : Microsoft TLS G2 RSA CA OCSP 04
leaf key                            : RSA 2048 bit
leaf signature algorithm            : sha384WithRSAEncryption
leaf validity                       : 2026-03-10 22:04:48Z .. 2026-09-24 22:04:48Z
first connection verify             : 0 (ok)
session ticket                      : yes, seen via post_handshake_newsessionticket, lifetime hint 83100
resumed on second connection        : yes, via tls13_psk
verify on the resumed connection    : 0 (ok)
peername reverified on resumption   : not reported
```

### learn.microsoft.com

Azure. Microsoft's own documentation site, served from Azure Front Door. Second Microsoft point of presence, same reason as the second AWS one.

```
address pinned for both connections : 23.212.193.214
all addresses resolved              : 23.212.193.214
negotiated                          : TLSv1.3, TLS_AES_256_GCM_SHA384, group X25519MLKEM768 (pq_hybrid)
chain                               : 3 certificates, 3725 DER bytes
leaf issuer CN                      : Microsoft TLS G2 ECC CA OCSP 02
leaf key                            : EC 256 bit P-256
leaf signature algorithm            : ecdsa-with-SHA384
leaf validity                       : 2025-12-16 02:26:09Z .. 2026-12-11 02:26:09Z
first connection verify             : 0 (ok)
session ticket                      : yes, seen via post_handshake_newsessionticket, lifetime hint 83100
resumed on second connection        : yes, via tls13_psk
verify on the resumed connection    : 0 (ok)
peername reverified on resumption   : not reported
```

### www.cloudflare.com

Cloudflare. Cloudflare's own product site, served from Cloudflare.

```
address pinned for both connections : 104.16.123.96
all addresses resolved              : 104.16.123.96, 104.16.124.96
negotiated                          : TLSv1.3, TLS_AES_256_GCM_SHA384, group X25519MLKEM768 (pq_hybrid)
chain                               : 3 certificates, 2493 DER bytes
leaf issuer CN                      : WE1
leaf key                            : EC 256 bit P-256
leaf signature algorithm            : ecdsa-with-SHA256
leaf validity                       : 2026-08-14 20:26:17Z .. 2026-11-12 21:26:08Z
first connection verify             : 0 (ok)
session ticket                      : no, seen via nothing, lifetime hint -
resumed on second connection        : -
verify on the resumed connection    : - ()
peername reverified on resumption   : not reported
```

### developers.cloudflare.com

Cloudflare. Cloudflare's own developer documentation, served from Cloudflare Pages, which is a different product from the one in front of www.

```
address pinned for both connections : 104.16.2.189
all addresses resolved              : 104.16.2.189, 104.16.3.189, 104.16.4.189, 104.16.5.189, 104.16.6.189
negotiated                          : TLSv1.3, TLS_AES_256_GCM_SHA384, group X25519MLKEM768 (pq_hybrid)
chain                               : 3 certificates, 2515 DER bytes
leaf issuer CN                      : WE1
leaf key                            : EC 256 bit P-256
leaf signature algorithm            : ecdsa-with-SHA256
leaf validity                       : 2026-08-26 19:02:29Z .. 2026-11-24 20:02:25Z
first connection verify             : 0 (ok)
session ticket                      : no, seen via nothing, lifetime hint -
resumed on second connection        : -
verify on the resumed connection    : - ()
peername reverified on resumption   : not reported
```

### www.fastly.com

Fastly. Fastly's own product site, served from Fastly.

```
address pinned for both connections : 151.101.1.57
all addresses resolved              : 151.101.1.57, 151.101.129.57, 151.101.193.57, 151.101.65.57
negotiated                          : TLSv1.3, TLS_AES_128_GCM_SHA256, group X25519MLKEM768 (pq_hybrid)
chain                               : 2 certificates, 2530 DER bytes
leaf issuer CN                      : Certainly Intermediate R1
leaf key                            : RSA 2048 bit
leaf signature algorithm            : sha256WithRSAEncryption
leaf validity                       : 2026-08-25 19:32:00Z .. 2026-09-24 19:31:59Z
first connection verify             : 0 (ok)
session ticket                      : yes, seen via post_handshake_newsessionticket, lifetime hint 86400
resumed on second connection        : yes, via tls13_psk
verify on the resumed connection    : 0 (ok)
peername reverified on resumption   : not reported
```

### docs.fastly.com

Fastly. Fastly's own documentation site, served from Fastly.

```
address pinned for both connections : 151.101.1.91
all addresses resolved              : 151.101.1.91, 151.101.129.91, 151.101.193.91, 151.101.65.91
negotiated                          : TLSv1.3, TLS_AES_128_GCM_SHA256, group X25519MLKEM768 (pq_hybrid)
chain                               : 2 certificates, 2544 DER bytes
leaf issuer CN                      : Certainly Intermediate R1
leaf key                            : RSA 2048 bit
leaf signature algorithm            : sha256WithRSAEncryption
leaf validity                       : 2026-08-27 06:21:51Z .. 2026-09-26 06:21:50Z
first connection verify             : 0 (ok)
session ticket                      : yes, seen via post_handshake_newsessionticket, lifetime hint 86400
resumed on second connection        : yes, via tls13_psk
verify on the resumed connection    : 0 (ok)
peername reverified on resumption   : not reported
```

### ietf.org

Reference. The standards body that publishes RFC 8446. The paper quotes its chain.

```
address pinned for both connections : 104.16.44.99
all addresses resolved              : 104.16.44.99, 104.16.45.99
negotiated                          : TLSv1.3, TLS_AES_256_GCM_SHA384, group X25519MLKEM768 (pq_hybrid)
chain                               : 3 certificates, 2465 DER bytes
leaf issuer CN                      : WE1
leaf key                            : EC 256 bit P-256
leaf signature algorithm            : ecdsa-with-SHA256
leaf validity                       : 2026-08-15 20:17:11Z .. 2026-11-13 21:17:08Z
first connection verify             : 0 (ok)
session ticket                      : no, seen via nothing, lifetime hint -
resumed on second connection        : -
verify on the resumed connection    : - ()
peername reverified on resumption   : not reported
```

### letsencrypt.org

Reference. The CA whose issuance the paper's chain-size figures are drawn from.

```
address pinned for both connections : 35.157.26.135
all addresses resolved              : 35.157.26.135, 63.176.8.218
negotiated                          : TLSv1.3, TLS_AES_128_GCM_SHA256, group - (-)
chain                               : 4 certificates, 3576 DER bytes
leaf issuer CN                      : YE2
leaf key                            : EC 256 bit P-256
leaf signature algorithm            : ecdsa-with-SHA384
leaf validity                       : 2026-07-06 15:24:34Z .. 2026-10-04 15:24:33Z
first connection verify             : 0 (ok)
session ticket                      : yes, seen via post_handshake_newsessionticket, lifetime hint 604800
resumed on second connection        : yes, via tls13_psk
verify on the resumed connection    : 0 (ok)
peername reverified on resumption   : not reported
```

### github.com

Reference. A large first-party edge that is not one of the five providers above.

```
address pinned for both connections : 140.82.121.3
all addresses resolved              : 140.82.121.3
negotiated                          : TLSv1.3, TLS_AES_128_GCM_SHA256, group - (-)
chain                               : 3 certificates, 2719 DER bytes
leaf issuer CN                      : Sectigo Public Server Authentication CA DV E36
leaf key                            : EC 256 bit P-256
leaf signature algorithm            : ecdsa-with-SHA256
leaf validity                       : 2026-07-03 00:00:00Z .. 2026-09-30 23:59:59Z
first connection verify             : 0 (ok)
session ticket                      : yes, seen via post_handshake_newsessionticket, lifetime hint 7200
resumed on second connection        : no
verify on the resumed connection    : 0 (ok)
peername reverified on resumption   : github.com
```

### google.com

Reference. The Google Front End on its highest-volume name, against which cloud.google.com can be compared.

```
address pinned for both connections : 172.253.157.100
all addresses resolved              : 172.253.157.100, 172.253.157.101, 172.253.157.102, 172.253.157.113, 172.253.157.138, 172.253.157.139
negotiated                          : TLSv1.3, TLS_AES_256_GCM_SHA384, group X25519MLKEM768 (pq_hybrid)
chain                               : 3 certificates, 4812 DER bytes
leaf issuer CN                      : WR2
leaf key                            : EC 256 bit P-256
leaf signature algorithm            : sha256WithRSAEncryption
leaf validity                       : 2026-08-10 08:37:35Z .. 2026-11-02 08:37:34Z
first connection verify             : 0 (ok)
session ticket                      : no, seen via nothing, lifetime hint -
resumed on second connection        : -
verify on the resumed connection    : - ()
peername reverified on resumption   : not reported
```

### mozilla.org

Reference. Operator of a root programme, and the source of the client-side policy the paper leans on.

```
address pinned for both connections : 35.190.14.201
all addresses resolved              : 35.190.14.201
negotiated                          : TLSv1.3, TLS_AES_256_GCM_SHA384, group - (-)
chain                               : 3 certificates, 3954 DER bytes
leaf issuer CN                      : WR3
leaf key                            : RSA 2048 bit
leaf signature algorithm            : sha256WithRSAEncryption
leaf validity                       : 2026-07-23 16:01:49Z .. 2026-10-21 16:55:01Z
first connection verify             : 0 (ok)
session ticket                      : no, seen via nothing, lifetime hint -
resumed on second connection        : -
verify on the resumed connection    : - ()
peername reverified on resumption   : not reported
```

## What a verify code of 0 on a resumed connection means

It means the client's stored verification result was still 0. It does not mean the certificate was checked again on that connection: on a resumed TLS 1.3 handshake the server sends no Certificate message, and the client reports the chain it cached during the full handshake. The `peername reverified` line above is the visible trace of that: OpenSSL prints `Verified peername` when it has checked a name against a certificate the peer just sent, and does not print it on a resumed connection. That difference is the paper's subject, observed from the outside.

This harness reports what `s_client` reports. It does not decode the record layer, so it does not assert that no Certificate message was sent; it records the absence of the reverification line, which is a weaker and checkable claim.
