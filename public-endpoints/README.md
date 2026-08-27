# Public endpoints: what the certificate handshake actually does

The other four experiments in this repository run against implementations installed locally,
where the configuration is ours and every variable can be held still. This one is different in
kind. It measures public infrastructure, from the outside, as a client, and it can therefore
establish only what a client can see.

It asks two questions of each host in `panel.txt`:

1. What does the certificate handshake cost and contain? Negotiated version, cipher, key
   exchange group, chain length, chain bytes, and the leaf's key, signature algorithm, issuer
   and validity window.
2. Does the host issue a session ticket, and does it resume a connection that offers that ticket
   back?

The second is the headline. The paper's argument rests on resumption being available almost
everywhere, and that claim should be measured rather than cited.

## Scope, and why the boundary is where it is

This harness completes ordinary TLS handshakes. Every packet it sends is one a browser sends on
an ordinary second visit to a website: a ClientHello, a certificate verification, and later a
ClientHello carrying a PSK identity the server itself minted. It reads what comes back. That is
the whole of its behaviour.

It does not, and no edit to it should make it:

- send any client certificate, credential, token or authentication attempt of any kind
- **offer a session ticket to any host or SNI other than the one that issued it**
- make any request designed to test authorisation, access control, or a bypass of either
- send more than one HEAD request per connection, or more than two connections per host

The second exclusion is the one worth explaining, because it is precisely the experiment run in
`nginx-vhost-scope/` and `haproxy/`. Replaying a ticket minted at one virtual host against
another is the scope question, and it is the most interesting thing in this repository.

It is legitimate there because those are our processes, our certificates and our configuration.
We put the client-authentication requirement on one of the two virtual hosts, so when we replay
a ticket across them we are testing a control we ourselves installed, and the only party who can
be harmed by the answer is us.

Against third-party infrastructure it is a different act with the same shape. A ticket replayed
at an SNI that did not issue it is an attempt to reach one configuration with credentials minted
by another. Whether or not it succeeds, and whether or not the operator notices, that is probing
someone else's access control, and we have no standing to do it.

So this harness does not, and the restriction is structural rather than advisory. Each host gets
its own temporary directory, created when it is reached and destroyed before the next host
starts. When a session is saved, a provenance file naming the issuing host is written beside it.
The code path that offers a session back reads that file first and raises
`CrossHostReplayRefused` unless it names the host it is about to connect to. That is a real
check and not an `assert`, because assertions disappear under `python -O` and this is the one
invariant that has to hold in every interpreter mode. `selftest.sh` exercises it. There is no
way to reach a cross-host replay without removing it on purpose.

The consequence is that this experiment cannot say anything about scope on public
infrastructure. It measures availability and cost, not confinement. That is a real limitation
and should be stated as one in the paper rather than glossed.

## Method

The two rules the other experiments follow apply here as well, and the second one has a specific
shape for this measurement.

**Every measurement carries a control.** The harness records both connections in full, including
the parameters the second connection negotiated, so a claim about the second is checkable
against the first. The address is resolved once and pinned for both connections. That is a
control, not a convenience: a CDN name resolves to many edge nodes, and if the two connections
landed on different ones then a failure to resume would be a statement about ticket-key
distribution rather than about the server's willingness to resume, and the two would not be
distinguishable after the fact. Similarly, the SNI is the same string on both connections, and
the CA store used is recorded in `results.json`, so the verification result is reproducible
rather than dependent on whatever the operator's machine happened to trust.

**A negative result must be distinguishable from a test that never posed the question.** For
resumption this is exact: *a host that issues no ticket cannot be said to have refused to
resume.* Such a host never received an offer. So the harness does not attempt a second
connection when no session was saved, records `resumed: null` rather than `false`, and sets
`controls.negative_result_is_readable` to `false` with the reason attached. The printed summary
and `results.md` both list those hosts separately. A `no` in the resumed column means a ticket
was issued, saved, offered back to the same address under the same SNI, and the server chose a
full handshake anyway. Nothing else may be read as a refusal.

Every value the harness could not obtain is recorded as `null` next to a reason. There are no
defaults and no plausible fill-ins anywhere in the parsing: if OpenSSL did not print it, the
field is empty and says why.

## Running it

```bash
./selftest.sh          # offline, four phases, no packet leaves the machine
python3 probe.py --dry-run
python3 probe.py
```

Requirements: OpenSSL 3.x on `PATH` (3.6.3 here, as elsewhere in this repository), and Python 3
with nothing installed beyond the standard library.

**Run `selftest.sh` before the first real run.** The headline measurement is negative-capable,
so an instrument that simply could not see a resumption would report "did not resume" for every
host in the panel, and the run would look like a finding. The self-test points `probe.py` at
local `openssl s_server` instances whose behaviour is known, in four phases:

1. a server that issues tickets and resumes: the harness must see both
2. a server started with `-num_tickets 0`: the harness must refuse to call that a refusal
3. a closed port: the harness must record the failure and carry on
4. a saved session offered at a host that did not mint it: the scope guard must refuse it, run
   once normally and once under `python -O`

It makes its own throwaway certificate, cleans up after itself, and checks 35 named fields
across the first three phases. If it fails, `probe.py` output about the public panel is not
evidence.

`--dry-run` prints the exact `s_client` command line for every host and exits. It does not
resolve any name, because a DNS query is already a packet and the point of the flag is to let
the panel be inspected before anything is sent.

Useful flags: `--only HOST` (repeatable) to probe a single host, `--pause` for the gap between
hosts (3s default), `--hold` for how long each connection is held open after the request so a
post-handshake NewSessionTicket has time to arrive (2s default), `--cafile` to pin the trust
store, `--request none` to make no HTTP request at all.

## Volume

Two connections per host, one HEAD request each, a three second pause between hosts. Fourteen
hosts is twenty-eight connections and a little over two minutes. This is below the noise floor
of any host in the panel and is not repeated on a schedule.

## Output

`results.json` is the record: one object per host under `records`, plus a `run` object carrying
the OpenSSL version, the CA store, the panel's sha256, the platform, and every timing parameter
used. Figures for the paper should be recomputed from it rather than transcribed from prose.

`results.md` is the same run written up, in the shape of `../RESULTS.md`.

Neither file is committed until an actual run produces them. `selftest-out/` is scratch and is
ignored.

## Reading the certificate columns

`chain bytes` is the total DER size of the certificates in the `Certificate chain` section of
the first connection's transcript, which is what the server sent. It is scoped to that section
deliberately: `s_client` prints the leaf a second time under `Server certificate`, and on a
resumed connection it prints a certificate restored from the cached session, so a naive count of
PEM blocks would inflate the chain.

`PQ hybrid` is derived from the negotiated group name against an explicit table in `probe.py`.
An unrecognised name is reported as `unknown` with the raw string intact, never guessed into a
bucket. A name that contains `MLKEM` or `KYBER` but is not in the table is reported as
`contains_pq_primitive`, which is a weaker claim than "hybrid" and is labelled as such, because
the harness cannot tell from a name alone whether it carries a classical half.

`verify` on the resumed connection is the client's stored verification result, and it is worth
being careful about what it means. On a resumed TLS 1.3 handshake the server sends no
Certificate message; OpenSSL reports the chain and the result it cached during the full
handshake. A `0` there is not evidence that anything was re-checked. The visible trace of the
difference is the `Verified peername` line, which OpenSSL prints when it has checked a name
against a certificate the peer has just sent, and does not print on a resumed connection. The
harness records its presence and absence. It does not decode the record layer, so it does not
assert that no Certificate message was sent; it records the absence of the reverification line,
which is a weaker and checkable claim. That gap between "verified" and "re-verified" is the
paper's subject, seen from outside a client that anyone can run.

## The panel

`panel.txt` carries the hosts and, in a second column, why each one is there. Every entry is a
provider's own public marketing or documentation site. None is a customer deployment: a
customer's origin behind a provider's edge would make the measurement a statement about that
customer, which is not ours to make.

The provider labels in that file are inferred, from the served certificate, from response
headers, and from public documentation. They are not measured. These are CDN-fronted names, the
mapping from hostname to terminating edge can be wrong, can differ between points of presence,
and can change without notice. `results.json` keeps the label in a field called `panel_comment`
for exactly that reason: it is context, not a result.
