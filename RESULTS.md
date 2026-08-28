# Results

All five experiments were run on 28 August 2026, macOS 25.2.0, arm64 (Apple M1 Pro), against
the latest available release of every provider that could be installed and driven locally.

| provider | version tested | released | result |
|---|---|---|---|
| OpenSSL (server) | 3.6.3 | 9 Jun 2026 | resumption **accepts** an expired client certificate |
| OpenSSL (client) | 3.6.3 | 9 Jun 2026 | resumption **accepts** an expired server certificate |
| nginx | 1.31.4 | current stable | cross-vhost client-auth scope **not reproducible**; fix holds |
| Go crypto/tls | 1.27.0 | current stable | **re-establishes** certificate expiry and trust-anchor membership |
| HAProxy | 3.4.3-80ea565fd | 29 Jul 2026 | cross-frontend resumption **not reproducible** in this configuration |
| 14 public endpoints | measured 27 Aug 2026 | live | **14 of 14** issue a ticket, **13 of 14** resume, **11 of 14** already negotiate a post-quantum hybrid key exchange |

Every experiment carries a control. A negative result with no control is unreadable: it cannot
distinguish "the implementation refused" from "the test never posed the question". Where a test
looks for a bypass, a second control replays the same ticket at the host that minted it, which
proves the ticket was valid and offerable at the moment the bypass was attempted.

---

## 1. OpenSSL 3.6.3, server side: an expired CLIENT certificate on a resumed session

`mtls-openssl/`. Three connections, one variable, the client certificate's validity.

```
1. client certificate VALID,   full handshake  -> accepted (baseline)
2. client certificate EXPIRED, RESUMED         -> Reused, ACCEPTED      <-- the finding
3. client certificate EXPIRED, full handshake  -> REJECTED (control)
```

Server log for connection 3: `verify error:num=10:certificate has expired`, then
`tls_process_client_certificate:certificate verify failed`. The control fires, so the
acceptance on connection 2 is a real difference between the two paths and not a
misconfigured server. The server was run with `-Verify 1 -verify_return_error`; without
`-verify_return_error` the control passes and the experiment proves nothing.

## 2. OpenSSL 3.6.3, client side: an expired SERVER certificate on a resumed session

`firefox-client/`. Same shape, on the other side of the connection.

```
1. certificate VALID,   full handshake  -> Verify return code: 0  (baseline)
2. certificate EXPIRED, RESUMED         -> Verify return code: 0  <-- the finding
3. certificate EXPIRED, full handshake  -> Verify return code: 10 (certificate has expired)
```

The server's own log confirms what happened on the wire rather than what the client reported:
connection 2 is `RESUMED  cert_valid=False`.

## 3. nginx 1.31.4: cross-virtual-host client-certificate scope (CVE-2025-23419)

`nginx-vhost-scope/`. Two `server{}` blocks in one process, sharing one certificate, one CA and
one `ssl_session_ticket_key`, differing in exactly one directive, `ssl_verify_client`.

```
1. protected.test, full handshake, no client certificate -> refused (control)
2. mint a ticket at open.test                            -> ticket saved
3. replay that ticket at protected.test                  -> NOT resumed, request refused
4. replay the same ticket back at open.test              -> RESUMED (control)
```

Control 4 is what makes step 3 readable: the same ticket resumes at the host that issued it, so
it was valid and offerable, and step 3's full handshake is nginx declining it. **The fix holds
in current nginx.** This is the paper's flagship exhibit and it is no longer reproducible on a
current build, which is the outcome the paper predicts and should be stated as such.

## 4. Go crypto/tls 1.27.0: expiry and trust-anchor membership

`go-crypto-tls/`. One process, one listener, one ticket key. Only the condition under test
changes between connections; `GetConfigForClient` swaps the server's `ClientCAs` in place so the
session cache and ticket key stay identical.

```
A. CLIENT CERTIFICATE EXPIRY
  1. valid,   first connection        full handshake  ACCEPTED
  2. valid,   resumed                 RESUMED         ACCEPTED   (baseline: resumption works)
  3. EXPIRED, resumed                 full handshake  REJECTED (tls: expired certificate)
  4. EXPIRED, full handshake          full handshake  REJECTED (control)

B. TRUST ANCHOR REMOVED FROM ClientCAs
  1. root present, first connection   full handshake  ACCEPTED
  2. root present, resumed            RESUMED         ACCEPTED   (baseline: resumption works)
  3. root REMOVED, resumed            full handshake  REJECTED (tls: unknown certificate authority)
  4. root REMOVED, full handshake     full handshake  REJECTED (control)
```

In both A3 and B3 Go declined to resume and fell back to a full handshake, which then failed.
The baselines at A2 and B2 resumed, so the refusal is caused by the condition and not by an
inability to resume at all. **Go re-establishes both the temporal condition and anchor
membership.** This confirms the full-chain-expiry fix (1.25.6, 15 Jan 2026) and the
root-membership fix (1.25.7, 4 Feb 2026) are present and effective in 1.27.0. Neither
experiment tested revocation or authentication policy, and no claim is made about them.

## 5. HAProxy 3.4.3: cross-frontend resumption

`haproxy/`. Two frontends in one process, one certificate, one ticket lifetime, differing in
`verify none` against `verify required`.

```
1. protected frontend, full handshake, no client certificate -> refused (control)
2. mint a ticket on the open frontend                        -> ticket saved
3. replay that ticket on the protected frontend              -> NOT resumed, not served
4. replay the same ticket on the open frontend               -> RESUMED (control)
```

**This does not reproduce a bypass, and it does not verify what it was built to verify.**
Separate `bind` lines already carry separate session id contexts in 3.4.3, so a ticket does not
cross between them regardless of the August 2026 series. The series' companion commits target
`crt-list` filters and CA/CRL changes, which this configuration does not exercise; a test that
does would need those. What this run does establish is the version fact: the binary is
`3.4.3-80ea565fd 2026/07/29`, and the series commits are dated 14 to 25 August 2026, so this
stable release predates them.

---

## 6. Fourteen public endpoints: what the certificate handshake actually does

`public-endpoints/`. Two connections per host, both to the same pinned address and the same SNI:
one to mint a session ticket, one to offer it back. Nothing else. No credential is sent, and a
ticket is never offered to a host that did not issue it, which is enforced in code rather than
promised in prose. Against our own nginx and HAProxy that cross-host replay is the whole
experiment; against somebody else's infrastructure it would be probing their access control, so
this harness refuses to do it.

Panel: the five providers the paper names, each on their own marketing or documentation site
(AWS, Google Cloud, Azure, Cloudflare, Fastly), plus five reference points (ietf.org,
letsencrypt.org, github.com, google.com, mozilla.org).

**14 of 14 issued a session ticket. 13 of 14 resumed. 11 of 14 negotiated X25519MLKEM768.**

Three findings bear directly on the paper.

**Post-quantum key exchange is already the default at every provider the paper names.** AWS,
Google, Azure, Cloudflare and Fastly all negotiated the hybrid group without being asked; so did
ietf.org. The three that did not are letsencrypt.org, github.com and mozilla.org. The key
exchange layer has migrated already. Authentication is the layer that has not, and it is the one
that carries the bytes, which is the paper's subject and its urgency.

**github.com issues a ticket and then declines to resume it.** The ticket was minted, saved and
offered back to the same address and the same SNI, and the server completed a full handshake
instead. That is a clean readable negative rather than an inconclusive one: the control record
confirms the ticket was issued and offerable, so "did not resume" here means the server refused,
not that the question went unasked. It has since replicated: both runs of section 7 and the
independent TypeScript implementation in `quantakrypto/pqc-observatory` show the same thing.

It is **not** a fifth party for the paper's section 5. That roster is about resumption under
client authentication, and this is a plain connection with no client certificate anywhere in it.
The paper says so explicitly and this repository should not be read as claiming otherwise.

**Measured chain sizes span 2,465 to 5,785 bytes, median 3,650.** The paper's classical cost row
is built on 3,393 B measured at ietf.org on 25 August, which sits comfortably inside that range.
But ietf.org itself now serves 3 certificates totalling 2,465 B from a Cloudflare address, not
the 4 certificates totalling 3,393 B the paper recorded three days earlier. The paper dates that
measurement, so it is not wrong, but a single dated host is a weaker basis than a measured range,
and this run supplies the range.

Ticket lifetime hints run from 7,200 s at github.com to 604,800 s at letsencrypt.org, the latter
being exactly the seven-day maximum RFC 9846 permits.

Every record carries its controls: whether a ticket was issued, whether it was offerable, whether
both connections used the same address and the same SNI, and whether a negative result is
readable at all. A host that issues no ticket cannot be said to have refused to resume, and the
harness records that case as null rather than false.

---

## 7. The same panel, asked and not asked: 8 of 14 against 14 of 14

`public-endpoints/ticket-prompting/`. The same instrument and the same panel, run twice back to
back with one argument different: `--request none` against `--request head`.

**A silent connection drew a session ticket from 8 of 14 hosts. A single `HEAD /` drew one from
all 14.** The six that withhold until asked are every Google-fronted and every Cloudflare-fronted
name on the panel and nothing else: `cloud.google.com`, `google.com`, `mozilla.org`,
`www.cloudflare.com`, `developers.cloudflare.com` and `ietf.org`.

Two things follow for the paper.

**The corroboration is comparable to the figure it corroborates, and now demonstrably so.** The
94.8% the paper cites comes from a scan that probed "whether the servers support TLS and session
tickets by sending an HTTPS request" (Hebrok et al., section 5.1.1). Ours sends one too. Before
this experiment that agreement was an accident of how `probe.py` happened to be written; it is
now a recorded condition of the measurement, in both directions.

**A reader reproducing the figure with a bare handshake will not get it.** They would measure 8
of 14 and conclude the paper overstated the availability of resumption. The condition has to
travel with the claim, which is why it now appears in the paper's source note rather than only
here.

Two cautions, both recorded rather than smoothed over. The absence of a ticket on a silent
connection is bounded by the harness's two-second hold, not absolute. And `aws.amazon.com`
resumed on one run and refused on the next ninety seconds later, with a different ticket
lifetime hint each time despite the pinned address, so that address fronts more than one
ticket-issuing backend: **a single `resumed: false` from a CDN anycast address is not evidence of
a policy.** What distinguishes github.com is that its refusal is stable across every run and its
lifetime hint never moves.

---

## What these results mean for the paper

The two OpenSSL findings stand and are reproducible on the current release. The nginx result is
a fix confirmation, not a vulnerability: the flagship CVE is closed in current nginx, and the
paper's argument does not depend on it being open, since the paper's claim is about the absence
of a specification, not about a live exposure.

The Go result is the most consequential. It refines the survey: Go now re-establishes expiry
*and* anchor membership, which is more than the roster's one-line summary conveys and exactly
what the paper's own adjudication says ("fully discharges the temporal condition only; its root
check re-establishes anchor membership, but nothing of policy or revocation").

The HAProxy run is reported as inconclusive rather than as a negative, because the configuration
tested is not the one the August series changes.
