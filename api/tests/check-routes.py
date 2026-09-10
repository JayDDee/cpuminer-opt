#!/usr/bin/env python3
"""Diff the route table in api_routes.cpp against the contract in docs/api-rest.md.

The contract document is the authority for paths, verbs and privileges. This
catches the drift that is otherwise invisible until a client hits a 404: a route
implemented but undocumented, or documented but unrouted, or routed with the
wrong privilege.

It does NOT check response schemas — that needs a running miner. This is the
static half; the schema check is done against a live instance.

    python api/tests/check-routes.py
"""

import re
import sys

DOC = "docs/api-rest.md"
SRC = "api_routes.c"        # .cpp in the sibling; the checker is otherwise shared

# The contract's endpoint table. A row may name several paths separated by ' · ',
# and the availability columns are per miner kind.
ROW = re.compile(r"^\|\s*(GET|POST)\s*\|\s*(.+?)\s*\|\s*(read|write|control)\s*\|", re.M)

# { API_M_GET, "/api/v1/summary", API_PRIV_READ, true, h_summary },
ENTRY = re.compile(
    r"\{\s*API_M_(\w+)\s*,\s*\"([^\"]+)\"\s*,\s*API_PRIV_(\w+)\s*,\s*(true|false)\s*,", re.M)

PRIV = {"READ": "read", "WRITE": "write", "CONTROL": "control"}


def doc_routes():
    text = open(DOC, encoding="utf-8").read()
    out = {}
    for verb, paths, priv in ROW.findall(text):
        base = None
        for p in paths.split("·"):
            p = p.strip().strip("`").strip()
            if not p.startswith("/"):
                continue
            if base is None:
                # first path in the row is absolute and sets the directory that
                # any continuation entries are relative to
                base = p.rsplit("/", 1)[0]
            elif not p.startswith("/api/v1") and not p.startswith("/metrics"):
                p = base + p
            out[(verb.lower(), p)] = priv
    return out


def src_routes():
    text = open(SRC, encoding="utf-8").read()
    out = {}
    for method, path, priv, avail in ENTRY.findall(text):
        if method == "GET":
            verb = "get"
        elif method == "POST":
            verb = "post"
        else:
            continue
        out[(verb, path)] = (PRIV[priv], avail == "true")
    return out


def normalise(p):
    """A prefix route '/api/v1/pools/' implements '/api/v1/pools/{n}'."""
    p = re.sub(r"\{[^}]+\}$", "", p)
    return p.rstrip("/") or "/"


def main():
    doc = doc_routes()
    src = src_routes()

    dn = {(v, normalise(p)): pr for (v, p), pr in doc.items()}
    sn = {(v, normalise(p)): pr for (v, p), pr in src.items()}

    fail = 0

    missing = sorted(k for k in dn if k not in sn)
    if missing:
        fail += len(missing)
        print("DOCUMENTED BUT NOT ROUTED:")
        for v, p in missing:
            print("  %-5s %s" % (v.upper(), p))

    extra = sorted(k for k in sn if k not in dn)
    if extra:
        fail += len(extra)
        print("ROUTED BUT NOT DOCUMENTED:")
        for v, p in extra:
            print("  %-5s %s" % (v.upper(), p))

    for k in sorted(set(dn) & set(sn)):
        want = dn[k]
        got = sn[k][0]
        if want != got:
            fail += 1
            print("PRIVILEGE MISMATCH %-5s %s: contract=%s code=%s" % (k[0].upper(), k[1], want, got))

    served = sorted(p for (v, p), (pr, av) in sn.items() if av)
    not_yet = sorted(p for (v, p), (pr, av) in sn.items() if not av)
    print("\n%d routes in the contract, %d in the table (%d served, %d answering 501)"
          % (len(dn), len(sn), len(served), len(not_yet)))
    if not_yet:
        print("answering 501 for now:")
        for p in not_yet:
            print("   ", p)

    print("\nRESULT:", "PASS" if fail == 0 else "FAIL (%d)" % fail)
    return 1 if fail else 0


if __name__ == "__main__":
    sys.exit(main())
