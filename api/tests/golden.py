#!/usr/bin/env python3
"""Golden-output capture for cpuminer-opt's binary API.

Sends every READ command the API implements to a running miner and records the
exact bytes it replies with. Used as a regression gate: capture before a change,
capture after, diff. The binary protocol is a compatibility surface, so any diff
that is not explicitly intended is a defect.

    ./cpuminer -a <algo> --benchmark --api-bind 127.0.0.1:4048
    python3 api/tests/golden.py capture before.txt
    ...change something, rebuild...
    python3 api/tests/golden.py capture after.txt
    python3 api/tests/golden.py diff before.txt after.txt

Port defaults to 4048 (`default_api_listen`, cpu-miner.c) -- NOT ccminer's 4068.

WRITE COMMANDS ARE DELIBERATELY NOT SENT. `quit` terminates the miner and
`seturl` mutates the pool, so neither can appear in a capture that is supposed
to be repeatable against one running process. They need their own targeted test.

Replies are recorded verbatim except for the volatile fields listed in VOLATILE,
which change between two runs of the *same* binary (uptime, rates, telemetry)
and would otherwise drown the signal.

BEFORE TRUSTING A DIFF, RUN THE SAME-BINARY CONTROL:

    python3 api/tests/golden.py capture c1.txt
    python3 api/tests/golden.py capture c2.txt
    python3 api/tests/golden.py diff c1.txt c2.txt      # must be IDENTICAL

If that is not IDENTICAL the mask is too narrow and every later diff is noise.
The sibling miner's port of this harness shipped with exactly that defect and
reported normal counter drift as a regression.
"""

import re
import socket
import sys

HOST, PORT = "127.0.0.1", 4048

# Read commands only, plus the two error cases the protocol has to handle:
# neither "" nor "bogus" may produce silence.
COMMANDS = ["summary", "threads", "help", "bogus", ""]

# key=value pairs whose value legitimately differs between two runs of the SAME
# binary. Verified by capturing twice without rebuilding: anything that moves
# there is runtime state, not protocol.
#   summary: NAME VER API ALGO CPUS URL are stable; the rest below move.
VOLATILE = [
    "HS", "KHS", "ACC", "REJ", "SOL", "ACCMN", "DIFF",
    "TEMP", "FAN", "FREQ", "UPTIME", "TS",
]
VOL_RE = re.compile(r"\b(" + "|".join(VOLATILE) + r")=[^;|]*")

# Note, cpuminer-opt-specific: cpustatus() builds "CPU=%d;%sH/s=%.2f" where %s is
# a SCALE PREFIX from scale_hash_for_display(). The unit is part of the KEY, so a
# miner that drifts across a scale boundary renames the key (H/s -> kH/s) and a
# naive shape comparison reports a protocol change that never happened. Normalise
# the prefix, then mask the value.
RATE_RE = re.compile(r"\b([kMGT]?)H/s=[^;|]*")


def normalise_rate(text):
    return RATE_RE.sub("<u>H/s=<v>", text)


def shapes(text):
    """Key-list of each distinct record type; multi-record replies grow with
    thread count and uptime, so compare shape rather than content."""
    seen = []
    for rec in text.split("|"):
        rec = rec.strip()
        if not rec or "=" not in rec:
            continue
        keys = ";".join(kv.split("=", 1)[0] for kv in rec.split(";") if "=" in kv)
        if keys not in seen:
            seen.append(keys)
    return seen


def ask(cmd, timeout=5.0):
    """One command, one connection -- the protocol closes after each reply."""
    s = socket.create_connection((HOST, PORT), timeout=timeout)
    try:
        s.sendall((cmd + "|").encode())
        chunks = []
        while True:
            b = s.recv(65536)
            if not b:
                break
            chunks.append(b)
        return b"".join(chunks)
    finally:
        s.close()


def mask(text):
    return VOL_RE.sub(lambda m: m.group(1) + "=<v>", normalise_rate(text))


def capture(path):
    out = []
    for cmd in COMMANDS:
        label = cmd if cmd else "<empty>"
        try:
            raw = ask(cmd)
        except Exception as e:                      # noqa: BLE001 - report, don't raise
            out.append("=== %s ===\nTRANSPORT-ERROR: %s\n" % (label, e))
            continue
        text = raw.decode("utf-8", "replace")
        recs = [r for r in text.split("|") if r.strip()]
        # Shape-compare only replies that are actually key=value records and
        # accumulate with runtime. `help` is a plain newline-separated list with
        # no "=" at all: shape-comparing it yields an EMPTY shape, i.e. the
        # command table would be silently uncompared and a route added or
        # removed would pass the gate. Compare that verbatim instead.
        kv = any("=" in r for r in recs)
        if len(recs) > 1 and kv:
            body = "records-shape:\n  " + "\n  ".join(shapes(normalise_rate(text)))
        else:
            body = "replied=%s\n%s" % (bool(raw), mask(text))
        out.append("=== %s ===\n%s\n" % (label, body))
    body = "".join(out)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(body)
    silent = body.count("replied=False")
    print("wrote %s  (%d commands, %d silent)" % (path, len(COMMANDS), silent))
    return 0


def diff(a, b):
    la = open(a, encoding="utf-8").read().splitlines()
    lb = open(b, encoding="utf-8").read().splitlines()
    import difflib
    d = list(difflib.unified_diff(la, lb, a, b, lineterm="", n=1))
    if not d:
        print("IDENTICAL: %s == %s" % (a, b))
        return 0
    print("\n".join(d))
    print("\n%d diff lines - every one must be an intended change." % len(d))
    return 1


if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == "capture":
        sys.exit(capture(sys.argv[2]))
    if len(sys.argv) >= 4 and sys.argv[1] == "diff":
        sys.exit(diff(sys.argv[2], sys.argv[3]))
    print(__doc__)
    sys.exit(2)
