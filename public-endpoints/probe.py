#!/usr/bin/env python3
"""Certificate-handshake measurement against public TLS endpoints.

What this does, in full:

  1. resolves a hostname, pins one address, and completes an ordinary TLS handshake to it
  2. records the negotiated version, cipher, key exchange group, and the served chain
  3. notices whether the server issued a NewSessionTicket, and its lifetime hint
  4. opens a second connection TO THE SAME ADDRESS, offering that ticket back, and records
     whether the server resumed

That is the whole of it. Every one of those four steps is what a browser does on a second visit
to a site. Nothing here sends a credential, and nothing here offers a ticket anywhere other than
the host and SNI that minted it. See README.md, "Scope", for why the second restriction is not
negotiable.

Python 3 standard library only. The TLS work is done by `openssl s_client` in a subprocess
rather than by Python's `ssl` module, because s_client reports the two things the module does
not: the NewSessionTicket lifetime hint, and the negotiated group by name. Resumption itself is
observable from both, so that is not the deciding factor; the lifetime hint is.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone

# ---------------------------------------------------------------------------------------------
# Key exchange group classification.
#
# The paper cares whether the key exchange is a post-quantum hybrid, so the group name is
# recorded raw AND classified. The table is explicit rather than clever: an unrecognised name is
# reported as "unknown" with the raw string intact, never guessed into a bucket. The substring
# fallback below only ever moves a name from "unknown" to "contains_pq_primitive", which is a
# weaker claim than "hybrid" and is labelled as such.
# ---------------------------------------------------------------------------------------------

GROUP_CLASSES = {
    # classical
    "X25519": "classical",
    "X448": "classical",
    "P-256": "classical",
    "P-384": "classical",
    "P-521": "classical",
    "secp256r1": "classical",
    "secp384r1": "classical",
    "secp521r1": "classical",
    "ffdhe2048": "classical",
    "ffdhe3072": "classical",
    "ffdhe4096": "classical",
    "ffdhe6144": "classical",
    "ffdhe8192": "classical",
    # post-quantum hybrids, standardised names
    "X25519MLKEM768": "pq_hybrid",
    "X448MLKEM1024": "pq_hybrid",
    "SecP256r1MLKEM768": "pq_hybrid",
    "SecP384r1MLKEM1024": "pq_hybrid",
    "secp256r1MLKEM768": "pq_hybrid",
    "secp384r1MLKEM1024": "pq_hybrid",
    # post-quantum hybrids, pre-standard draft names still seen in the wild
    "X25519Kyber768Draft00": "pq_hybrid_draft",
    "X25519Kyber512Draft00": "pq_hybrid_draft",
    "P256Kyber768Draft00": "pq_hybrid_draft",
    "SecP256r1Kyber768Draft00": "pq_hybrid_draft",
    # pure post-quantum, no classical half
    "MLKEM512": "pq_only",
    "MLKEM768": "pq_only",
    "MLKEM1024": "pq_only",
}


def classify_group(group: str | None) -> dict:
    """Classify a negotiated group name. Returns the raw name alongside the verdict."""
    if group is None:
        return {"name": None, "class": None, "is_pq_hybrid": None}
    cls = GROUP_CLASSES.get(group)
    if cls is None:
        upper = group.upper()
        if "MLKEM" in upper or "KYBER" in upper:
            # Recognisably post-quantum, but this table does not know whether the name carries a
            # classical half. Say the weaker thing.
            cls = "contains_pq_primitive"
        else:
            cls = "unknown"
    return {
        "name": group,
        "class": cls,
        "is_pq_hybrid": cls in ("pq_hybrid", "pq_hybrid_draft"),
    }


KEY_ALGORITHM_NAMES = {
    "rsaEncryption": "RSA",
    "id-ecPublicKey": "EC",
    "ED25519": "Ed25519",
    "ED448": "Ed448",
    "id-Ed25519": "Ed25519",
}


# ---------------------------------------------------------------------------------------------
# Panel
# ---------------------------------------------------------------------------------------------


def read_panel(path: str) -> list[dict]:
    entries: list[dict] = []
    seen: set[str] = set()
    with open(path, encoding="utf-8") as handle:
        for lineno, raw in enumerate(handle, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            host = parts[0]
            comment = parts[1].strip() if len(parts) > 1 else ""
            if host in seen:
                raise SystemExit(
                    f"{path}:{lineno}: {host} appears twice. "
                    "Duplicates would double the connection count without adding a measurement."
                )
            seen.add(host)
            entries.append({"host": host, "comment": comment, "line": lineno})
    if not entries:
        raise SystemExit(f"{path}: no hosts.")
    return entries


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


# ---------------------------------------------------------------------------------------------
# openssl plumbing
# ---------------------------------------------------------------------------------------------


def openssl_version(openssl: str) -> str | None:
    try:
        out = subprocess.run(
            [openssl, "version"], capture_output=True, text=True, timeout=15
        )
        return out.stdout.strip() or None
    except (OSError, subprocess.SubprocessError):
        return None


def openssl_dir(openssl: str) -> str | None:
    try:
        out = subprocess.run(
            [openssl, "version", "-d"], capture_output=True, text=True, timeout=15
        )
        match = re.search(r'OPENSSLDIR:\s*"(.*)"', out.stdout)
        return match.group(1) if match else None
    except (OSError, subprocess.SubprocessError):
        return None


def supports_dateopt(openssl: str) -> bool:
    """OpenSSL 3.0 added -dateopt. Older builds must fall back to the human date format."""
    try:
        out = subprocess.run(
            [openssl, "x509", "-help"], capture_output=True, text=True, timeout=15
        )
        return "-dateopt" in (out.stdout + out.stderr)
    except (OSError, subprocess.SubprocessError):
        return False


def format_connect(ip: str, port: int) -> str:
    return f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"


def s_client_argv(
    openssl: str,
    ip: str,
    port: int,
    host: str,
    cafile: str | None,
    sess_out: str | None,
    sess_in: str | None,
    showcerts: bool,
) -> list[str]:
    """Build the s_client command line.

    Two properties of this command line carry the whole scope guarantee, so they are stated here
    rather than left to be inferred:

      -servername/-verify_hostname are ALWAYS `host`, on both the minting and the offering
      connection. There is no code path that sets them to anything else.

      -connect is a pinned IP address, the same one on both connections. That is not a
      convenience: if the two connections landed on different edge nodes, a failure to resume
      would be a statement about ticket-key distribution and not about the server's willingness
      to resume, and the two are not distinguishable after the fact.
    """
    argv = [
        openssl,
        "s_client",
        "-connect",
        format_connect(ip, port),
        "-servername",
        host,
        "-verify_hostname",
        host,
        "-verify",
        "8",
        # No -verify_return_error. The verification result is a measurement here, so the
        # handshake must be allowed to complete and report it rather than aborting on it.
        "-no_ssl3",
        "-no_tls1",
        "-no_tls1_1",
    ]
    if cafile:
        argv += ["-CAfile", cafile]
    if showcerts:
        argv += ["-showcerts"]
    if sess_out:
        argv += ["-sess_out", sess_out]
    if sess_in:
        argv += ["-sess_in", sess_in]
    return argv


def run_s_client(argv: list[str], host: str, request: str, hold: float, timeout: float) -> dict:
    """Run one s_client connection and return its transcript plus how it ended.

    `hold` keeps stdin open after the request is written. That matters: in TLS 1.3 the
    NewSessionTicket is a post-handshake message, so a client that shuts down the moment it has
    sent its request can miss a ticket the server did in fact issue, and would then record
    "no ticket" for a host that issues one. The hold is the difference between measuring the
    server and measuring our own impatience.
    """
    if request == "head":
        payload = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    elif request == "get":
        payload = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    elif request == "none":
        payload = ""
    else:
        raise ValueError(request)

    # `payload` then a sleep, fed through a shell, is how stdin is held open without threads.
    # The payload is not interpolated into the shell command; it is written by python -c with the
    # hostname passed as argv, so a hostile panel entry cannot reach the shell.
    holder = [
        sys.executable,
        "-c",
        "import sys,time\n"
        "sys.stdout.write(sys.argv[1])\n"
        "sys.stdout.flush()\n"
        "time.sleep(float(sys.argv[2]))\n",
        payload,
        str(hold),
    ]

    started = time.monotonic()
    try:
        feeder = subprocess.Popen(holder, stdout=subprocess.PIPE)
    except OSError as exc:
        return {"ok": False, "how_it_ended": "spawn_failure", "error": str(exc), "text": ""}

    try:
        proc = subprocess.run(
            argv,
            stdin=feeder.stdout,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
        )
        text = proc.stdout + proc.stderr
        ended = "exited"
        returncode = proc.returncode
    except subprocess.TimeoutExpired as exc:
        # A timeout is a recorded outcome, not a crash. Whatever s_client managed to print before
        # the deadline is still evidence and is kept.
        text = ""
        for stream in (exc.stdout, exc.stderr):
            if stream:
                text += stream.decode("utf-8", "replace") if isinstance(stream, bytes) else stream
        ended = "timeout"
        returncode = None
    except OSError as exc:
        return {"ok": False, "how_it_ended": "spawn_failure", "error": str(exc), "text": ""}
    finally:
        if feeder.stdout:
            feeder.stdout.close()
        try:
            feeder.kill()
        except OSError:
            pass
        feeder.wait()

    return {
        "ok": True,
        "how_it_ended": ended,
        "returncode": returncode,
        "text": text,
        "wall_seconds": round(time.monotonic() - started, 3),
        "error": None,
    }


# ---------------------------------------------------------------------------------------------
# Transcript parsing. Every extractor returns None when the value was not present, and the
# caller records the None. There are no defaults anywhere in this section.
# ---------------------------------------------------------------------------------------------

RE_NEW = re.compile(r"^New, (\S+), Cipher is (\S+)", re.M)
RE_REUSED = re.compile(r"^Reused, (\S+), Cipher is (\S+)", re.M)
RE_PROTOCOL = re.compile(r"^\s*Protocol\s*:?\s*(TLSv[0-9.]+)", re.M)
RE_GROUP = re.compile(r"^Negotiated (?:TLS1\.3 )?group:\s*(\S+)", re.M)
RE_VERIFY = re.compile(r"^\s*Verify return code:\s*(\d+)\s*\((.*)\)", re.M)
RE_PEERNAME = re.compile(r"^Verified peername:\s*(\S+)", re.M)
RE_TICKET = re.compile(r"^Post-Handshake New Session Ticket arrived:", re.M)
RE_LIFETIME = re.compile(r"^\s*TLS session ticket lifetime hint:\s*(\d+)", re.M)
RE_TICKET_MATERIAL = re.compile(r"^\s*TLS session ticket:\s*$", re.M)
RE_SESSION_ID = re.compile(r"^\s*Session-ID:\s*([0-9A-Fa-f]+)\s*$", re.M)
# Tried in order against a transcript from a connection that produced no handshake. The first
# that matches becomes the recorded reason, so a refused connection is not reported with the same
# generic wording as a rejected certificate.
FAILURE_PATTERNS = [
    re.compile(r"^connect:errno=\d+.*$", re.M),
    re.compile(r"^.*:(?:Connection refused|Connection reset|No route to host|Operation timed out).*$", re.M),
    re.compile(r"^.*:alert [a-z ]+:.*$", re.M),
    re.compile(r"^\s*SSL alert number \d+.*$", re.M),
    re.compile(r"^.*:error:[0-9A-Fa-f]+:.*$", re.M),
    re.compile(r"^\s*Verify return code:\s*\d+ \(.*\)\s*$", re.M),
]


def failure_reason(text: str, how_it_ended: str) -> str:
    for pattern in FAILURE_PATTERNS:
        match = pattern.search(text)
        if match:
            return match.group(0).strip()
    if how_it_ended == "timeout":
        return "the connection produced no handshake before the timeout"
    if not text.strip():
        return "openssl produced no output"
    return "no 'New,' or 'Reused,' line in the transcript"
RE_PEM = re.compile(
    r"-----BEGIN CERTIFICATE-----\s*(.*?)-----END CERTIFICATE-----", re.S
)


def parse_handshake(text: str) -> dict:
    """Pull the negotiated parameters out of an s_client transcript."""
    new = RE_NEW.search(text)
    reused = RE_REUSED.search(text)
    protocol = RE_PROTOCOL.search(text)
    verify = RE_VERIFY.search(text)
    group = RE_GROUP.search(text)
    peername = RE_PEERNAME.search(text)

    version = None
    cipher = None
    if reused:
        version, cipher = reused.group(1), reused.group(2)
    elif new:
        version, cipher = new.group(1), new.group(2)
    elif protocol:
        version = protocol.group(1)

    handshake_completed = bool(new or reused)

    return {
        "handshake_completed": handshake_completed,
        "tls_version": version,
        "cipher": cipher,
        "key_exchange_group": classify_group(group.group(1) if group else None),
        "verify_return_code": int(verify.group(1)) if verify else None,
        "verify_return_text": verify.group(2) if verify else None,
        # Present on a full handshake where the name was checked against a certificate the server
        # actually sent. Absent on a resumed handshake, where no Certificate message arrives.
        # Recorded as an observation, not as proof that no certificate was sent: this harness
        # reads s_client's report, it does not decode the record layer.
        "verified_peername": peername.group(1) if peername else None,
        "reused_line_present": bool(reused),
    }


def parse_tickets(text: str) -> dict:
    """Record whether a session ticket was received, and its lifetime hint.

    There are two routes by which one can appear, and they are not the same event:

      TLS 1.3 sends NewSessionTicket after the handshake, and s_client announces each one with a
      `Post-Handshake New Session Ticket arrived:` banner. Hints are scoped to the text following
      a banner, because s_client also prints a full SSL-Session block on exit and that block
      repeats the last hint; counting it as well would double the ticket count.

      TLS 1.2 sends its ticket during the handshake, so there is no banner. The only trace is the
      `TLS session ticket:` block in the SSL-Session dump.

    A harness that looked only for the banner would report "no ticket" for every TLS 1.2 host
    that issues one, so both routes are checked and the route taken is recorded.
    """
    banners = list(RE_TICKET.finditer(text))
    hints: list[int] = []
    for index, banner in enumerate(banners):
        end = banners[index + 1].start() if index + 1 < len(banners) else len(text)
        hint = RE_LIFETIME.search(text, banner.end(), end)
        if hint:
            hints.append(int(hint.group(1)))

    ticket_material = bool(RE_TICKET_MATERIAL.search(text))
    session_ids = [m.group(1) for m in RE_SESSION_ID.finditer(text)]

    if banners:
        observed_via = "post_handshake_newsessionticket"
    elif ticket_material:
        observed_via = "session_block_only"
        # No banner to scope to, so take the last hint printed anywhere.
        all_hints = [int(m.group(1)) for m in RE_LIFETIME.finditer(text)]
        hints = all_hints[-1:] if all_hints else []
    else:
        observed_via = None

    issued = observed_via is not None
    if hints:
        reason = None
    elif issued:
        reason = "a ticket was received but no lifetime hint line appeared in the transcript"
    else:
        reason = "no session ticket observed before the connection ended"

    return {
        "issued": issued,
        "observed_via": observed_via,
        "post_handshake_banner_count": len(banners),
        "ticket_material_present": ticket_material,
        "session_id_present": bool(session_ids),
        # -sess_out saves the LAST session offered to the client, so the last hint is the one
        # belonging to the ticket the second connection will offer back.
        "lifetime_hint_seconds": hints[-1] if hints else None,
        "lifetime_hints_observed": hints,
        "unavailable_reason": reason,
    }


def resumption_mechanism(tls_version: str | None, ticket: dict) -> tuple[str | None, str | None]:
    """Name the mechanism a successful resumption rode on, and admit where it is ambiguous.

    This exists because "no ticket, but resumed" is a coherent row rather than a contradiction.
    TLS 1.2 can resume on a session identifier alone, with no ticket anywhere in the exchange, so
    a harness that equated resumption with tickets would either miss those resumptions or invent
    tickets to explain them.
    """
    if tls_version == "TLSv1.3":
        # TLS 1.3 has one resumption mechanism: a PSK, which in practice is carried by a ticket.
        return "tls13_psk", None
    if tls_version == "TLSv1.2":
        if ticket.get("ticket_material_present"):
            return (
                "tls12_session_ticket_or_session_id",
                "the client offered both a ticket and a session identifier, and s_client's output "
                "does not say which the server used",
            )
        return (
            "tls12_session_id",
            "no ticket was received, so the resumption can only have used the session identifier",
        )
    return None, f"unrecognised TLS version {tls_version!r}"


def parse_chain_pems(text: str) -> list[bytes] | None:
    """Return the DER bytes of each certificate in the `Certificate chain` section.

    Scoped to that section deliberately. s_client prints the leaf a second time under
    `Server certificate`, and on a resumed connection it prints a certificate restored from the
    cached session; counting either would inflate the chain.
    """
    match = re.search(r"^Certificate chain\n(.*?)^---\s*$", text, re.S | re.M)
    if not match:
        return None
    ders: list[bytes] = []
    for body in RE_PEM.findall(match.group(1)):
        try:
            ders.append(base64.b64decode("".join(body.split()), validate=True))
        except (binascii.Error, ValueError):
            return None
    return ders or None


def split_rfc2253(dn: str) -> list[tuple[str, str]]:
    """Split an RFC 2253 distinguished name, honouring backslash escapes."""
    fields: list[str] = []
    current: list[str] = []
    escaped = False
    for char in dn:
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
            current.append(char)
        elif char == ",":
            fields.append("".join(current))
            current = []
        else:
            current.append(char)
    fields.append("".join(current))
    out: list[tuple[str, str]] = []
    for field in fields:
        if "=" in field:
            key, _, value = field.partition("=")
            out.append((key.strip(), value.strip().replace("\\,", ",")))
    return out


def describe_leaf(openssl: str, der: bytes, dateopt: bool, timeout: float) -> dict:
    """Read the leaf certificate's properties with the openssl x509 tool.

    Deliberately not parsed out of the `a:`/`v:` summary lines that s_client prints next to each
    chain entry. Those lines are formatted differently for RSA and EC keys and are absent
    entirely on OpenSSL 3.0, so a harness that reads them reports different things on different
    machines. This is offline: no network, one temporary file, deleted before returning.
    """
    out = {
        "subject": None,
        "issuer": None,
        "issuer_cn": None,
        "signature_algorithm": None,
        "key_type": None,
        "key_algorithm_oid_name": None,
        "key_bits": None,
        "key_curve": None,
        "not_before": None,
        "not_after": None,
        "der_bytes": len(der),
        "sha256": hashlib.sha256(der).hexdigest(),
        "unavailable_reason": None,
    }

    handle, path = tempfile.mkstemp(suffix=".der")
    try:
        with os.fdopen(handle, "wb") as fh:
            fh.write(der)

        def x509(*args: str) -> str | None:
            try:
                proc = subprocess.run(
                    [openssl, "x509", "-in", path, "-inform", "DER", "-noout", *args],
                    capture_output=True,
                    text=True,
                    errors="replace",
                    timeout=timeout,
                )
            except (OSError, subprocess.SubprocessError):
                return None
            return proc.stdout if proc.returncode == 0 else None

        names = x509("-subject", "-issuer", "-nameopt", "RFC2253")
        if names:
            for line in names.splitlines():
                if line.startswith("subject="):
                    out["subject"] = line[len("subject=") :].strip()
                elif line.startswith("issuer="):
                    out["issuer"] = line[len("issuer=") :].strip()
            if out["issuer"]:
                for key, value in split_rfc2253(out["issuer"]):
                    if key.upper() == "CN":
                        out["issuer_cn"] = value
                        break

        dates = x509("-dates", "-dateopt", "iso_8601") if dateopt else x509("-dates")
        if dates:
            for line in dates.splitlines():
                if line.startswith("notBefore="):
                    out["not_before"] = line[len("notBefore=") :].strip()
                elif line.startswith("notAfter="):
                    out["not_after"] = line[len("notAfter=") :].strip()

        text = x509("-text", "-nameopt", "RFC2253")
        if text:
            sig = re.search(r"^\s*Signature Algorithm:\s*(\S+)", text, re.M)
            if sig:
                out["signature_algorithm"] = sig.group(1)
            alg = re.search(r"^\s*Public Key Algorithm:\s*(\S+)", text, re.M)
            if alg:
                out["key_algorithm_oid_name"] = alg.group(1)
                out["key_type"] = KEY_ALGORITHM_NAMES.get(alg.group(1), alg.group(1))
            bits = re.search(r"^\s*(?:Public-Key|ML-DSA-\S+ Public-Key):\s*\((\d+) bit\)", text, re.M)
            if bits:
                out["key_bits"] = int(bits.group(1))
            curve = re.search(r"^\s*NIST CURVE:\s*(\S+)", text, re.M)
            if curve:
                out["key_curve"] = curve.group(1)
        else:
            out["unavailable_reason"] = "openssl x509 -text failed on the leaf"
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass

    return out


# ---------------------------------------------------------------------------------------------
# One host
# ---------------------------------------------------------------------------------------------


def resolve(host: str, port: int, family_pref: str) -> dict:
    """Resolve a hostname and pin one address.

    Deterministic on purpose: the addresses are sorted and the first is taken, so two runs with
    the same DNS answer probe the same node and are comparable.
    """
    order = {
        "ipv4": [socket.AF_INET, socket.AF_INET6],
        "ipv6": [socket.AF_INET6, socket.AF_INET],
        "any": [socket.AF_UNSPEC],
    }[family_pref]

    all_addresses: list[str] = []
    chosen: str | None = None
    error: str | None = None
    for family in order:
        try:
            infos = socket.getaddrinfo(host, port, family, socket.SOCK_STREAM)
        except socket.gaierror as exc:
            error = f"{exc.__class__.__name__}: {exc}"
            continue
        addresses = sorted({info[4][0] for info in infos})
        for address in addresses:
            if address not in all_addresses:
                all_addresses.append(address)
        if addresses and chosen is None:
            chosen = addresses[0]
            error = None
        if chosen is not None and family_pref != "any":
            break

    return {"addresses": all_addresses, "chosen": chosen, "error": error}


class CrossHostReplayRefused(RuntimeError):
    """Raised rather than offer a session ticket at a host that did not issue it."""


def check_session_provenance(sess_path: str, minted_by: str, host: str) -> None:
    """Refuse to offer a session unless its provenance file names the host we are about to visit.

    Replaying a ticket at an SNI that did not mint it is the scope experiment. Against our own
    nginx and HAProxy it is legitimate and is exactly what `../nginx-vhost-scope` and
    `../haproxy` do, because those are our processes and our configuration. Against third-party
    infrastructure it is probing someone else's access control, so this harness will not do it.

    This is a real check and not an assertion, because assertions disappear under `python -O` and
    this is the one invariant that must hold in every interpreter mode. It reads a file written
    at minting time, so it survives a future refactor that passes a session in from elsewhere.
    """
    try:
        with open(minted_by, encoding="utf-8") as handle:
            issuer = handle.read().strip()
    except OSError as exc:
        raise CrossHostReplayRefused(
            f"{sess_path}: no provenance record, so the issuing host is unknown ({exc})"
        ) from exc
    if issuer != host:
        raise CrossHostReplayRefused(
            f"{sess_path} was minted by {issuer!r} and would be offered to {host!r}. "
            "Refusing: see README.md, 'Scope'."
        )


def probe_host(entry: dict, cfg: argparse.Namespace, env: dict) -> dict:
    host = entry["host"]
    record: dict = {
        "host": host,
        "panel_comment": entry["comment"],
        "measured_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds").replace(
            "+00:00", "Z"
        ),
        "outcome": None,
        "error": None,
        "port": cfg.port,
        "addresses_resolved": None,
        "ip": None,
        "connection_1_full_handshake": None,
        "certificate_chain": None,
        "session_ticket": None,
        "connection_2_resumption": None,
        "controls": None,
    }

    dns = resolve(host, cfg.port, cfg.family)
    record["addresses_resolved"] = dns["addresses"]
    record["ip"] = dns["chosen"]
    if dns["chosen"] is None:
        record["outcome"] = "dns_failure"
        record["error"] = dns["error"] or "no address returned"
        return record

    # Each host gets its own directory, created fresh and destroyed before the next host starts.
    # No session file can outlive its host, which is what makes a cross-host replay impossible
    # here by construction rather than by discipline.
    workdir = tempfile.mkdtemp(prefix="probe-")
    try:
        sess_path = os.path.join(workdir, "session.pem")
        minted_by = os.path.join(workdir, "minted-by")

        argv1 = s_client_argv(
            cfg.openssl,
            dns["chosen"],
            cfg.port,
            host,
            cfg.cafile,
            sess_out=sess_path,
            sess_in=None,
            showcerts=True,
        )
        first = run_s_client(argv1, host, cfg.request, cfg.hold, cfg.timeout)
        if not first["ok"]:
            record["outcome"] = "openssl_spawn_failure"
            record["error"] = first["error"]
            return record

        hs1 = parse_handshake(first["text"])
        hs1["how_it_ended"] = first["how_it_ended"]
        hs1["wall_seconds"] = first.get("wall_seconds")
        record["connection_1_full_handshake"] = hs1

        if not hs1["handshake_completed"]:
            record["outcome"] = (
                "timeout" if first["how_it_ended"] == "timeout" else "handshake_failure"
            )
            record["error"] = failure_reason(first["text"], first["how_it_ended"])
            # A failure is a result and has to be auditable, so the tail of what openssl actually
            # said is kept rather than summarised away.
            record["transcript_tail"] = first["text"][-600:] or None
            return record

        # --- chain ---------------------------------------------------------------------------
        ders = parse_chain_pems(first["text"])
        if ders is None:
            record["certificate_chain"] = {
                "count": None,
                "der_bytes_total": None,
                "der_bytes_per_certificate": None,
                "leaf": None,
                "unavailable_reason": "no parseable 'Certificate chain' section in the transcript",
            }
        else:
            record["certificate_chain"] = {
                "count": len(ders),
                "der_bytes_total": sum(len(d) for d in ders),
                "der_bytes_per_certificate": [len(d) for d in ders],
                "leaf": describe_leaf(cfg.openssl, ders[0], env["dateopt"], cfg.timeout),
                "unavailable_reason": None,
            }

        # --- ticket --------------------------------------------------------------------------
        tickets = parse_tickets(first["text"])
        session_written = os.path.exists(sess_path) and os.path.getsize(sess_path) > 0
        if session_written:
            # Provenance, written next to the session at the moment it is minted. The second
            # connection refuses to offer a session whose provenance file does not name the host
            # it is about to connect to. See offer_session_or_refuse below.
            with open(minted_by, "w", encoding="utf-8") as handle:
                handle.write(host)
        tickets["session_file_written"] = session_written
        tickets["session_file_bytes"] = (
            os.path.getsize(sess_path) if session_written else None
        )
        record["session_ticket"] = tickets

        # --- resumption ----------------------------------------------------------------------
        if not session_written:
            record["connection_2_resumption"] = {
                "attempted": False,
                "not_attempted_reason": (
                    "no session was saved, so there was nothing to offer back. This is NOT a "
                    "refusal to resume: the question was never posed."
                ),
                "resumed": None,
                "mechanism": None,
                "mechanism_note": None,
                "handshake_completed": None,
                "tls_version": None,
                "cipher": None,
                "key_exchange_group": classify_group(None),
                "verify_return_code": None,
                "verify_return_text": None,
                "verified_peername": None,
                "how_it_ended": None,
            }
        else:
            # The ticket goes back to the host that minted it, and to nowhere else.
            check_session_provenance(sess_path, minted_by, host)

            time.sleep(cfg.resume_gap)
            argv2 = s_client_argv(
                cfg.openssl,
                dns["chosen"],  # same address, not a fresh resolution
                cfg.port,
                host,  # same SNI, same hostname verification
                cfg.cafile,
                sess_out=None,
                sess_in=sess_path,
                showcerts=False,
            )
            second = run_s_client(argv2, host, cfg.request, cfg.hold, cfg.timeout)
            if not second["ok"]:
                record["connection_2_resumption"] = {
                    "attempted": True,
                    "not_attempted_reason": None,
                    "resumed": None,
                    "handshake_completed": None,
                    "error": second["error"],
                    "how_it_ended": second["how_it_ended"],
                }
            else:
                hs2 = parse_handshake(second["text"])
                resumed = hs2["reused_line_present"] if hs2["handshake_completed"] else None
                mechanism, mechanism_note = (
                    resumption_mechanism(hs2["tls_version"], tickets)
                    if resumed
                    else (None, None)
                )
                record["connection_2_resumption"] = {
                    "attempted": True,
                    "not_attempted_reason": None,
                    "resumed": resumed,
                    "mechanism": mechanism,
                    "mechanism_note": mechanism_note,
                    "handshake_completed": hs2["handshake_completed"],
                    "tls_version": hs2["tls_version"],
                    "cipher": hs2["cipher"],
                    "key_exchange_group": hs2["key_exchange_group"],
                    "verify_return_code": hs2["verify_return_code"],
                    "verify_return_text": hs2["verify_return_text"],
                    "verified_peername": hs2["verified_peername"],
                    "verification_ok": (
                        hs2["verify_return_code"] == 0
                        if hs2["verify_return_code"] is not None
                        else None
                    ),
                    "how_it_ended": second["how_it_ended"],
                    "wall_seconds": second.get("wall_seconds"),
                }

        record["outcome"] = "measured"
        record["controls"] = build_controls(record)
        return record
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def build_controls(record: dict) -> dict:
    """The controls that decide whether this record's resumption line may be read at all."""
    ticket = record.get("session_ticket") or {}
    resumption = record.get("connection_2_resumption") or {}
    hs1 = record.get("connection_1_full_handshake") or {}

    ticket_issued = bool(ticket.get("issued"))
    offerable = bool(ticket.get("session_file_written"))
    attempted = bool(resumption.get("attempted"))
    resumed = resumption.get("resumed")

    if resumed is True:
        readable = True
        reason = "the host resumed, which is a positive result and needs no further control"
    elif not offerable:
        readable = False
        reason = (
            "no session was saved, so no ticket was offered. A host that issues no ticket "
            "cannot be said to have refused to resume."
        )
    elif not attempted:
        readable = False
        reason = "the second connection was not attempted"
    elif resumption.get("handshake_completed") is not True:
        readable = False
        reason = (
            "the second connection did not complete a handshake, so the refusal cannot be "
            "attributed to the ticket"
        )
    else:
        readable = True
        reason = (
            "a ticket was issued, saved and offered back to the same address and SNI, and the "
            "server completed a full handshake instead of resuming"
        )

    return {
        "server_issued_a_ticket": ticket_issued,
        "ticket_observed_via": ticket.get("observed_via"),
        "ticket_was_offerable": offerable,
        "resumption_was_attempted": attempted,
        "both_connections_used_the_same_address": True,
        "both_connections_used_the_same_sni": True,
        "first_connection_verified_ok": (
            hs1.get("verify_return_code") == 0
            if hs1.get("verify_return_code") is not None
            else None
        ),
        "negative_result_is_readable": readable,
        "readability_reason": reason,
    }


# ---------------------------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------------------------


def plural(count: int, singular: str, suffix: str = "s") -> str:
    return f"{count} {singular}" if count == 1 else f"{count} {singular}{suffix}"


def cell(value, absent: str = "-") -> str:
    if value is None:
        return absent
    if value is True:
        return "yes"
    if value is False:
        return "no"
    return str(value)


def print_summary(records: list[dict]) -> None:
    headers = [
        "host",
        "ip",
        "ver",
        "group",
        "pq",
        "chain",
        "bytes",
        "ticket",
        "life(s)",
        "resumed",
        "via",
        "vfy",
    ]
    rows: list[list[str]] = []
    for rec in records:
        hs1 = rec.get("connection_1_full_handshake") or {}
        chain = rec.get("certificate_chain") or {}
        ticket = rec.get("session_ticket") or {}
        resume = rec.get("connection_2_resumption") or {}
        group = hs1.get("key_exchange_group") or {}

        if rec["outcome"] != "measured":
            rows.append(
                [rec["host"], cell(rec.get("ip")), rec["outcome"]] + ["-"] * (len(headers) - 3)
            )
            continue

        rows.append(
            [
                rec["host"],
                cell(rec.get("ip")),
                cell(hs1.get("tls_version")).replace("TLSv", ""),
                cell(group.get("name")),
                cell(group.get("is_pq_hybrid")),
                cell(chain.get("count")),
                cell(chain.get("der_bytes_total")),
                cell(ticket.get("issued")),
                cell(ticket.get("lifetime_hint_seconds")),
                cell(resume.get("resumed")),
                cell(resume.get("mechanism")),
                cell(resume.get("verify_return_code")),
            ]
        )

    widths = [
        max(len(headers[i]), *(len(row[i]) for row in rows)) if rows else len(headers[i])
        for i in range(len(headers))
    ]
    line = "  ".join(h.ljust(widths[i]) for i, h in enumerate(headers))
    print(line)
    print("  ".join("-" * widths[i] for i in range(len(headers))))
    for row in rows:
        print("  ".join(row[i].ljust(widths[i]) for i in range(len(headers))))
    print()
    unreadable = [
        r["host"]
        for r in records
        if (r.get("controls") or {}).get("negative_result_is_readable") is False
    ]
    if unreadable:
        print(
            "Not readable as a refusal to resume (no ticket was offerable): "
            + ", ".join(unreadable)
        )
    failed = [r["host"] for r in records if r["outcome"] != "measured"]
    if failed:
        print("Not measured: " + ", ".join(failed))


def write_results_md(path: str, meta: dict, records: list[dict]) -> None:
    measured = [r for r in records if r["outcome"] == "measured"]
    resumed = [r for r in measured if (r.get("connection_2_resumption") or {}).get("resumed") is True]
    ticketed = [r for r in measured if (r.get("session_ticket") or {}).get("issued")]
    hybrids = [
        r
        for r in measured
        if ((r.get("connection_1_full_handshake") or {}).get("key_exchange_group") or {}).get(
            "is_pq_hybrid"
        )
    ]

    out: list[str] = []
    add = out.append
    add("# Public endpoints: what the certificate handshake does\n")
    add(
        f"Run on {meta['started_utc']}, from {meta['openssl_version'] or 'an unidentified OpenSSL'}, "
        f"against the {plural(len(records), 'host')} in `{meta['panel']}` "
        f"(sha256 `{meta['panel_sha256'][:16]}`). Two connections per host: one to mint a "
        "session ticket, one to offer it back to the same address and the same SNI.\n"
    )
    add(
        "This is a measurement of ordinary client behaviour against public infrastructure. It "
        "reads certificates and observes whether a resumption offer is accepted. It sends no "
        "credential, and it never offers a ticket to a host other than the one that issued it. "
        "See [README.md](README.md) for why that second restriction is a boundary and not a "
        "preference.\n"
    )
    add("## Summary\n")
    add(
        f"- {len(measured)} of {plural(len(records), 'host')} measured; "
        f"{len(records) - len(measured)} could not be.\n"
        f"- {len(ticketed)} issued a session ticket.\n"
        f"- {len(resumed)} resumed a connection that offered that ticket back.\n"
        f"- {len(hybrids)} negotiated a post-quantum hybrid key exchange group.\n"
    )
    add(
        "| host | ip | version | group | PQ hybrid | chain | chain bytes | ticket | lifetime (s) "
        "| resumed | via | verify |"
    )
    add("|---|---|---|---|---|---|---|---|---|---|---|---|")
    for rec in records:
        hs1 = rec.get("connection_1_full_handshake") or {}
        chain = rec.get("certificate_chain") or {}
        ticket = rec.get("session_ticket") or {}
        resume = rec.get("connection_2_resumption") or {}
        group = hs1.get("key_exchange_group") or {}
        if rec["outcome"] != "measured":
            add(f"| {rec['host']} | {cell(rec.get('ip'))} | **{rec['outcome']}** | | | | | | | | | |")
            continue
        add(
            "| {host} | {ip} | {ver} | {grp} | {pq} | {n} | {b} | {tk} | {life} | {res} | {via} "
            "| {vfy} |".format(
                host=rec["host"],
                ip=cell(rec.get("ip")),
                ver=cell(hs1.get("tls_version")),
                grp=cell(group.get("name")),
                pq=cell(group.get("is_pq_hybrid")),
                n=cell(chain.get("count")),
                b=cell(chain.get("der_bytes_total")),
                tk=cell(ticket.get("issued")),
                life=cell(ticket.get("lifetime_hint_seconds")),
                res=cell(resume.get("resumed")),
                via=cell(resume.get("mechanism")),
                vfy=cell(resume.get("verify_return_code")),
            )
        )
    add("")
    add(
        "A row reading ticket `no`, resumed `yes` is not a contradiction. TLS 1.2 can resume on a "
        "session identifier with no ticket in the exchange at all, and the `via` column says "
        "which mechanism carried it. In TLS 1.3 there is only one, a PSK, and it comes from a "
        "ticket.\n"
    )
    add("## Reading the resumption column\n")
    add(
        "A blank or `no` in the resumed column is only a statement about the server if a ticket "
        "was issued and offered back. Where it was not, the question was never posed and the "
        "row says nothing about that host's willingness to resume. The hosts in that position "
        "in this run:\n"
    )
    unreadable = [
        r for r in records if (r.get("controls") or {}).get("negative_result_is_readable") is False
    ]
    if unreadable:
        for rec in unreadable:
            add(f"- `{rec['host']}`: {(rec.get('controls') or {}).get('readability_reason')}")
    else:
        add("- none: every host that failed to resume had a ticket to offer.")
    add("")
    add("## Per host\n")
    for rec in records:
        add(f"### {rec['host']}\n")
        add(f"{rec['panel_comment']}\n")
        if rec["outcome"] != "measured":
            add(f"Not measured: **{rec['outcome']}**. {cell(rec.get('error'), '')}\n")
            continue
        hs1 = rec["connection_1_full_handshake"]
        chain = rec["certificate_chain"]
        ticket = rec["session_ticket"]
        resume = rec["connection_2_resumption"]
        leaf = (chain or {}).get("leaf") or {}
        group = hs1.get("key_exchange_group") or {}
        add("```")
        add(f"address pinned for both connections : {rec['ip']}")
        add(f"all addresses resolved              : {', '.join(rec['addresses_resolved'])}")
        add(f"negotiated                          : {cell(hs1.get('tls_version'))}, "
            f"{cell(hs1.get('cipher'))}, group {cell(group.get('name'))} ({cell(group.get('class'))})")
        count = (chain or {}).get("count")
        add(f"chain                               : "
            f"{plural(count, 'certificate') if isinstance(count, int) else '-'}, "
            f"{cell((chain or {}).get('der_bytes_total'))} DER bytes")
        add(f"leaf issuer CN                      : {cell(leaf.get('issuer_cn'))}")
        add(f"leaf key                            : {cell(leaf.get('key_type'))} "
            f"{cell(leaf.get('key_bits'))} bit {cell(leaf.get('key_curve'), '')}".rstrip())
        add(f"leaf signature algorithm            : {cell(leaf.get('signature_algorithm'))}")
        add(f"leaf validity                       : {cell(leaf.get('not_before'))} .. "
            f"{cell(leaf.get('not_after'))}")
        add(f"first connection verify             : {cell(hs1.get('verify_return_code'))} "
            f"({cell(hs1.get('verify_return_text'), '')})")
        add(f"session ticket                      : {cell(ticket.get('issued'))}, seen via "
            f"{cell(ticket.get('observed_via'), 'nothing')}, lifetime hint "
            f"{cell(ticket.get('lifetime_hint_seconds'))}")
        add(f"resumed on second connection        : {cell(resume.get('resumed'))}"
            f"{'' if not resume.get('mechanism') else ', via ' + resume['mechanism']}")
        add(f"verify on the resumed connection    : {cell(resume.get('verify_return_code'))} "
            f"({cell(resume.get('verify_return_text'), '')})")
        add(f"peername reverified on resumption   : {cell(resume.get('verified_peername'), 'not reported')}")
        add("```")
        add("")

    add("## What a verify code of 0 on a resumed connection means\n")
    add(
        "It means the client's stored verification result was still 0. It does not mean the "
        "certificate was checked again on that connection: on a resumed TLS 1.3 handshake the "
        "server sends no Certificate message, and the client reports the chain it cached during "
        "the full handshake. The `peername reverified` line above is the visible trace of that: "
        "OpenSSL prints `Verified peername` when it has checked a name against a certificate the "
        "peer just sent, and does not print it on a resumed connection. That difference is the "
        "paper's subject, observed from the outside.\n"
    )
    add(
        "This harness reports what `s_client` reports. It does not decode the record layer, so "
        "it does not assert that no Certificate message was sent; it records the absence of the "
        "reverification line, which is a weaker and checkable claim.\n"
    )

    with open(path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(out).rstrip() + "\n")


# ---------------------------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------------------------


def dry_run(entries: list[dict], cfg: argparse.Namespace, env: dict) -> None:
    """Print exactly what would happen. Sends nothing, including no DNS query.

    Name resolution is a packet, so a dry run that resolved would already have contacted the
    network, which is the one thing the operator asked it not to do before inspecting the panel.
    The address in each command line is therefore shown as a placeholder.
    """
    print("DRY RUN. No packet is sent, and no name is resolved.\n")
    print(f"openssl            : {cfg.openssl} ({env['openssl_version'] or 'version unreadable'})")
    print(f"OPENSSLDIR         : {env['openssl_dir'] or 'unreadable'}")
    print(f"CA file            : {cfg.cafile or 'openssl default trust store'}")
    print(f"panel              : {cfg.panel} (sha256 {env['panel_sha256']})")
    print(f"port               : {cfg.port}")
    print(f"address family     : {cfg.family}")
    print(f"request per conn   : {cfg.request.upper() if cfg.request != 'none' else 'none'}")
    print(f"hold after request : {cfg.hold}s (so a post-handshake ticket has time to arrive)")
    print(f"per-connection cap : {cfg.timeout}s")
    print(f"gap between conns  : {cfg.resume_gap}s")
    print(f"pause between hosts: {cfg.pause}s")
    print(f"output directory   : {cfg.out_dir}")
    print()
    print(f"{len(entries)} hosts, 2 connections each, {len(entries) * 2} connections total.")
    print(
        f"Estimated wall time if nothing times out: about "
        f"{int(len(entries) * (cfg.pause + cfg.resume_gap + 2 * cfg.hold + 2))}s.\n"
    )
    for entry in entries:
        host = entry["host"]
        one = s_client_argv(
            cfg.openssl, "<resolved-ip>", cfg.port, host, cfg.cafile,
            sess_out="<tmp>/session.pem", sess_in=None, showcerts=True,
        )
        two = s_client_argv(
            cfg.openssl, "<resolved-ip>", cfg.port, host, cfg.cafile,
            sess_out=None, sess_in="<tmp>/session.pem", showcerts=False,
        )
        print(f"{host}")
        print(f"    why    : {entry['comment']}")
        print(f"    mint   : {' '.join(one)}")
        print(f"    offer  : {' '.join(two)}")
        print(f"    SNI on both connections: {host}. The session file never leaves this host.")
        print()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Probe public TLS endpoints and record what their certificate handshake does.",
    )
    here = os.path.dirname(os.path.abspath(__file__))
    parser.add_argument("--panel", default=os.path.join(here, "panel.txt"))
    parser.add_argument("--out-dir", default=here)
    parser.add_argument("--openssl", default=os.environ.get("OPENSSL", "openssl"))
    parser.add_argument("--cafile", default=None, help="CA bundle; default is openssl's own store")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--family", choices=["ipv4", "ipv6", "any"], default="ipv4")
    parser.add_argument("--request", choices=["head", "get", "none"], default="head")
    parser.add_argument("--timeout", type=float, default=20.0, help="cap per connection, seconds")
    parser.add_argument(
        "--hold",
        type=float,
        default=2.0,
        help="seconds to hold the connection open after the request, so a post-handshake "
        "NewSessionTicket has time to arrive",
    )
    parser.add_argument("--resume-gap", type=float, default=1.0, help="seconds between the two connections")
    parser.add_argument("--pause", type=float, default=3.0, help="seconds between hosts")
    parser.add_argument("--only", action="append", default=None, help="restrict to this host; repeatable")
    parser.add_argument("--dry-run", action="store_true")
    cfg = parser.parse_args(argv)

    if shutil.which(cfg.openssl) is None and not os.path.isabs(cfg.openssl):
        print(f"openssl not found: {cfg.openssl}", file=sys.stderr)
        return 2

    entries = read_panel(cfg.panel)
    if cfg.only:
        wanted = set(cfg.only)
        entries = [e for e in entries if e["host"] in wanted]
        missing = wanted - {e["host"] for e in entries}
        if missing:
            print(f"not in the panel: {', '.join(sorted(missing))}", file=sys.stderr)
            return 2

    version = openssl_version(cfg.openssl)
    env = {
        "openssl_version": version,
        "openssl_dir": openssl_dir(cfg.openssl),
        "panel_sha256": sha256_file(cfg.panel),
        "dateopt": supports_dateopt(cfg.openssl),
    }

    if cfg.dry_run:
        dry_run(entries, cfg, env)
        return 0

    if version is None:
        print(f"could not read the version of {cfg.openssl}", file=sys.stderr)
        return 2

    os.makedirs(cfg.out_dir, exist_ok=True)
    started = datetime.now(timezone.utc)
    records: list[dict] = []
    for index, entry in enumerate(entries):
        if index:
            time.sleep(cfg.pause)
        print(f"[{index + 1}/{len(entries)}] {entry['host']}", file=sys.stderr, flush=True)
        try:
            record = probe_host(entry, cfg, env)
        except Exception as exc:  # a bad host must not end the run
            record = {
                "host": entry["host"],
                "panel_comment": entry["comment"],
                "measured_at_utc": datetime.now(timezone.utc)
                .isoformat(timespec="seconds")
                .replace("+00:00", "Z"),
                "outcome": "harness_error",
                "error": f"{exc.__class__.__name__}: {exc}",
            }
        records.append(record)

    finished = datetime.now(timezone.utc)
    meta = {
        "started_utc": started.isoformat(timespec="seconds").replace("+00:00", "Z"),
        "finished_utc": finished.isoformat(timespec="seconds").replace("+00:00", "Z"),
        "openssl_version": env["openssl_version"],
        "openssl_dir": env["openssl_dir"],
        "ca_file": cfg.cafile,
        "ca_source": cfg.cafile or "openssl default trust store",
        "panel": os.path.basename(cfg.panel),
        "panel_sha256": env["panel_sha256"],
        "port": cfg.port,
        "address_family_preference": cfg.family,
        "request_per_connection": cfg.request,
        "hold_seconds": cfg.hold,
        "timeout_seconds": cfg.timeout,
        "resume_gap_seconds": cfg.resume_gap,
        "pause_between_hosts_seconds": cfg.pause,
        "connections_per_host": 2,
        "platform": " ".join(os.uname()) if hasattr(os, "uname") else sys.platform,
        "scope": (
            "Certificate handshake only. No client certificate, no credential, no authorisation "
            "test. Every session ticket is offered back only to the host and SNI that issued it."
        ),
    }

    json_path = os.path.join(cfg.out_dir, "results.json")
    with open(json_path, "w", encoding="utf-8") as handle:
        json.dump({"run": meta, "records": records}, handle, indent=2, sort_keys=False)
        handle.write("\n")

    md_path = os.path.join(cfg.out_dir, "results.md")
    write_results_md(md_path, meta, records)

    print()
    print_summary(records)
    print()
    print(f"wrote {json_path}")
    print(f"wrote {md_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
