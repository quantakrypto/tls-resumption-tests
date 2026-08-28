# Does the server volunteer a ticket, or does it wait to be asked?

`../probe.py` measures whether a host issues a session ticket. It cannot, on its own, say
whether the host issues one unprompted or only once a request arrives. Those are different
facts about a deployment, and the difference decides what a measurement of "does resumption
exist here" is worth.

It matters for two reasons.

The first is reproducibility. Anyone checking the paper's figure by opening a bare TLS
connection and looking for a NewSessionTicket will get a different number from ours, conclude
we were wrong, and be right to. The gap is not small.

The second is comparability. The internet-scale figure the paper cites, 94.8% of reachable TLS
domains issuing a ticket, comes from a scan that probed "whether the servers support TLS and
session tickets by sending an HTTPS request" (Hebrok et al., section 5.1.1). Our corroboration
is only comparable to theirs because it sends one too. Before this experiment that was an
accident of how `probe.py` was written. Now it is a recorded condition of the measurement.

## Method

One instrument, one panel, one argument different. `probe.py` already carries `--request
none`, so no new measurement code was written for this: the two runs differ in exactly that
flag, which is the whole reason the comparison is worth anything.

```bash
./run.sh          # selftest, then both runs, then the table below
python3 compare.py   # regenerate the table from the two result files
```

The runs go back to back rather than in parallel. The panel is CDN-fronted, and two
simultaneous runs would land on different edge nodes, which would put a second uncontrolled
variable next to the one being tested.

Every figure below is printed by `compare.py` from the two JSON files beside it. None is typed
in by hand, so an edited sentence and the recorded measurement cannot quietly drift apart.

## Result

    silent run : 2026-08-28T01:14:28Z to 2026-08-28T01:16:03Z, request=none
    HEAD run   : 2026-08-28T01:16:03Z to 2026-08-28T01:17:09Z, request=head
    openssl    : OpenSSL 3.6.3 9 Jun 2026 (Library: OpenSSL 3.6.3 9 Jun 2026)
    panel      : f05931e024c211d5, hold 2.0s

| host | ticket, silent | banners | ticket, one HEAD | banners | lifetime hint s | resumed, silent | resumed, HEAD |
|---|---|---|---|---|---|---|---|
| `aws.amazon.com` | yes | 1 | yes | 1 | 56146 | yes | no |
| `docs.aws.amazon.com` | yes | 1 | yes | 1 | 77738 | yes | yes |
| `cloud.google.com` | no | 0 | yes | 2 | 172800 | - | yes |
| `azure.microsoft.com` | yes | 2 | yes | 2 | 83100 | yes | yes |
| `learn.microsoft.com` | yes | 2 | yes | 2 | 83100 | yes | yes |
| `www.cloudflare.com` | no | 0 | yes | 2 | 64800 | - | yes |
| `developers.cloudflare.com` | no | 0 | yes | 2 | 64800 | - | yes |
| `www.fastly.com` | yes | 1 | yes | 1 | 86400 | yes | yes |
| `docs.fastly.com` | yes | 1 | yes | 1 | 86400 | yes | yes |
| `ietf.org` | no | 0 | yes | 2 | 64800 | - | yes |
| `letsencrypt.org` | yes | 1 | yes | 1 | 604800 | yes | yes |
| `github.com` | yes | 2 | yes | 2 | 7200 | no | no |
| `google.com` | no | 0 | yes | 2 | 172800 | - | yes |
| `mozilla.org` | no | 0 | yes | 2 | 172800 | - | yes |

**8 of 14 hosts issue a session ticket on a connection that sends nothing. All 14 issue one
after a single `HEAD /`.** The six that withhold are `cloud.google.com`, `google.com`,
`mozilla.org`, `www.cloudflare.com`, `developers.cloudflare.com` and `ietf.org`: every
Google-fronted and every Cloudflare-fronted name on the panel, and nothing else. AWS, Azure,
Fastly, Let's Encrypt and GitHub volunteer one.

`mozilla.org` and `ietf.org` are worth naming separately, because neither is a cloud provider
in the panel's sense. They land in the withholding group by whose edge terminates their TLS,
Google's and Cloudflare's, which is the point: this is a property of the terminating stack, not
of the site's own policy.

The banner counts carry a second, smaller observation. The withholding stacks send two tickets
when they send any; AWS, Fastly and Let's Encrypt send one. That is a configuration difference
visible from outside and it is recorded here rather than interpreted.

## What this does not show

**"No ticket on a silent connection" is bounded, not absolute.** The bound is the harness's
hold, two seconds here, recorded as `hold_seconds` in both files. A server that volunteers a
ticket after three seconds of silence would be recorded as withholding. The claim is "none
arrived while the connection was held open", and it should be read that way.

**It says nothing about why.** Withholding until a request arrives is an unremarkable
implementation choice, and this experiment offers no evidence about the reason for it. It is
not a defect and is not presented as one.

**The provider labels are inferences.** They come from the served certificate and public
documentation, not from measurement. See `../panel.txt`.

## Two things that replicated, and one that did not

`github.com` issued a ticket and then completed a full handshake when that ticket was offered
back to the same pinned address under the same SNI. That now holds in both runs here and in the
committed run of 27 August, three observations across two days, and again in the independent
TypeScript implementation in `quantakrypto/pqc-observatory`, in both its silent and its
request-sending modes. It is a readable
negative: the controls confirm a ticket was issued and offerable.

Chain sizes did not move at all between 27 and 28 August. Every host served the same number of
certificates totalling the same DER bytes, so the range the paper quotes, 2,465 to 5,785 B with
a median of 3,650, is a second-day replication rather than a single reading.

`aws.amazon.com` did not replicate, and the reason is worth stating carefully, because the
obvious summary of it is wrong. The silent run resolved to 143.204.238.22 and resumed there. The
HEAD run, ninety seconds later, resolved to 13.32.121.33 and was refused. So the flip is not one
address changing its mind: the two runs reached different edges.

The within-address evidence is separate and is what carries the point. 13.32.121.33 resumed on
27 August and refused on 28 August, with ticket lifetime hints of 72,108 and 56,146 seconds. Each
run pinned a single address across both of its connections, so every individual result here is
readable, but the outcome is not a property of the host. **A single `resumed: false` from a CDN
anycast address is therefore not evidence of a policy**, and nothing in the paper rests on one.
What distinguishes `github.com` is that its refusal is stable across every run, at one address,
with a lifetime hint that never moves.
