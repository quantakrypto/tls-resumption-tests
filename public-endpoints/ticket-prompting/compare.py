#!/usr/bin/env python3
"""Print the silent-versus-HEAD comparison from the two result files.

Every figure in README.md is produced by this script and none is typed by hand. The two runs
are read as JSON and the counts are derived, so an edited prose figure and the recorded
measurement cannot drift apart without the table disagreeing with the file beside it.

Null is never printed as "no". A host that issued no ticket was never offered one back, so its
resumption cell is "-", meaning the question was not put, not that the server declined.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TRI = {True: "yes", False: "no", None: "-"}


def load(name: str) -> dict:
    path = os.path.join(HERE, name)
    if not os.path.exists(path):
        sys.exit(f"{name} is missing. Run ./run.sh first; nothing here is fabricated.")
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def by_host(doc: dict) -> dict:
    return {r["host"]: r for r in doc["records"]}


def cell(v) -> str:
    return "-" if v is None else str(v)


def main() -> int:
    silent, head = load("silent-results.json"), load("head-results.json")
    S, H = by_host(silent), by_host(head)

    if silent["run"]["panel_sha256"] != head["run"]["panel_sha256"]:
        sys.exit("the two runs used different panels; the comparison would be meaningless")
    if silent["run"]["request_per_connection"] == head["run"]["request_per_connection"]:
        sys.exit("both runs sent the same thing; there is no comparison to draw")

    print(f"silent run : {silent['run']['started_utc']} to {silent['run']['finished_utc']}, "
          f"request={silent['run']['request_per_connection']}")
    print(f"HEAD run   : {head['run']['started_utc']} to {head['run']['finished_utc']}, "
          f"request={head['run']['request_per_connection']}")
    print(f"openssl    : {silent['run']['openssl_version']}")
    print(f"panel      : {silent['run']['panel_sha256'][:16]}, hold {silent['run']['hold_seconds']}s\n")

    print("| host | ticket, silent | banners | ticket, one HEAD | banners | lifetime hint s "
          "| resumed, silent | resumed, HEAD |")
    print("|---|---|---|---|---|---|---|---|")
    withheld = []
    for host in H:
        a, b = S.get(host), H[host]
        if a is None:
            continue
        sa, sb = a["session_ticket"], b["session_ticket"]
        ra, rb = a["connection_2_resumption"], b["connection_2_resumption"]
        print(f"| `{host}` | {TRI[sa['issued']]} | {cell(sa['post_handshake_banner_count'])} "
              f"| {TRI[sb['issued']]} | {cell(sb['post_handshake_banner_count'])} "
              f"| {cell(sb['lifetime_hint_seconds'])} "
              f"| {TRI[ra['resumed']]} | {TRI[rb['resumed']]} |")
        if not sa["issued"] and sb["issued"]:
            withheld.append(host)

    si = sum(1 for h in S if S[h]["session_ticket"]["issued"])
    hi = sum(1 for h in H if H[h]["session_ticket"]["issued"])
    print(f"\nticket issued, silent connection : {si} of {len(S)}")
    print(f"ticket issued, one HEAD          : {hi} of {len(H)}")
    print(f"withheld until a request arrived : {len(withheld)}")
    for host in withheld:
        print(f"  {host}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
