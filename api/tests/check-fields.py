#!/usr/bin/env python3
"""Reconcile the fields a running miner emits against docs/openapi.yaml.

The contract is written before the handlers, so it drifts in both directions:
a field can be documented and never emitted, or emitted and never documented.
Neither shows up as an error anywhere else -- a client just finds a null it did
not expect, or misses a value that was there all along.

    <run a miner with --api-bind 127.0.0.1:4048>
    python api/tests/check-fields.py                 # live
    python api/tests/check-fields.py captured.json   # from a saved capture

Needs PyYAML for the schema side.
"""

import json
import sys
import urllib.request

try:
    import yaml
except ImportError:
    print("check-fields: PyYAML is required"); sys.exit(2)

SPEC = "docs/openapi.yaml"
BASE = "http://127.0.0.1:4048/api/v1/"

# endpoint -> (schema name, json key holding it, True if it is an array)
# The only fields the contract allows to be absent rather than null.
# Device: "a common shell plus a typed sub-object naming the device class, and
# on one implementation a second naming the compute stack ... clients must
# tolerate any sub-object being absent". Health: reasons accompanies a
# degraded status. Anything else missing is drift.
CONDITIONAL = {
    "Device": {"gpu", "cpu", "vulkan"},
    "Health": {"reasons"},
}

# Fields this miner emits that the shared schema does not describe yet, named
# one by one rather than waved through by a prefix: the whole value of this
# check is that an undocumented field is loud, and a wildcard here would make
# the next one silent.
#
# They are reported apart from the drift rather than counted as it because the
# schema is one file that several implementations ship, and it is edited in all
# of them at once. Adding the field to this repo's copy first and reconciling
# afterwards is how the document forks; this list is what carries the debt in
# the meantime, and it is empty when there is none.
PENDING = {}

BINDINGS = [
    ("summary",   "Summary",     "summary", False),
    ("threads",   "Thread",      "threads", True),
    ("devices/0", "Device",      "device",  False),
    ("system",    "System",      "system",  False),
    ("pools/0",   "Pool",        "pool",    False),
    ("health",    "Health",      "health",  False),
    # Only present with --api-control; skipped when the route answers 403/501.
    ("control/state", "ControlState", "control", False),
]


def schema_props(spec, name):
    """Property names of a component schema, one level deep plus sub-objects."""
    s = spec["components"]["schemas"][name]
    out = {}
    out["__required__"] = set(s.get("required") or [])
    for k, v in (s.get("properties") or {}).items():
        sub = None
        if isinstance(v, dict) and v.get("type") == "object" and v.get("properties"):
            sub = set(v["properties"].keys())
        elif isinstance(v, dict) and "$ref" in v:
            ref = v["$ref"].split("/")[-1]
            rs = spec["components"]["schemas"].get(ref, {})
            sub = set((rs.get("properties") or {}).keys())
        out[k] = sub
    return out


def emitted(obj):
    out = {}
    for k, v in obj.items():
        out[k] = set(v.keys()) if isinstance(v, dict) else None
    return out


def fetch(ep, cache):
    if cache is not None:
        return cache.get(ep)
    try:
        return json.load(urllib.request.urlopen(BASE + ep, timeout=8))
    except urllib.error.HTTPError as e:
        # A degraded /health is 503 and carries the health object rather than an
        # error envelope. That is the one non-2xx with fields to reconcile, and
        # skipping it would leave the reasons array unchecked in exactly the
        # state it exists for.
        if e.code == 503:
            return json.load(e)
        # 403 (control switched off) and 501 (not served by this miner) are
        # contract-legal answers, not drift; anything else is a real failure.
        if e.code in (403, 501):
            return None
        raise


def main():
    cache = None
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    if args:
        cache = json.load(open(args[0], encoding="utf-8"))
    spec = yaml.safe_load(open(SPEC, encoding="utf-8"))

    fail = 0
    for ep, schema, key, is_array in BINDINGS:
        body = fetch(ep, cache)
        if body is None or "ERROR" in body:
            print("%-12s SKIP (not reachable)" % ep); continue
        payload = body.get(key)
        if is_array:
            if not payload:
                print("%-12s SKIP (empty array)" % ep); continue
            payload = payload[0]

        want = schema_props(spec, schema)
        want.pop("__required__", None)
        got = emitted(payload)

        # docs/api-rest.md section 3: "Unavailable values are null, never 0 and
        # never omitted." So a documented field that is absent IS a fault --
        # except for the handful the contract explicitly says are conditional.
        allowed = CONDITIONAL.get(schema, set())
        pending = PENDING.get(schema, set())
        absent = set(want) - set(got)
        missing = sorted(absent - allowed)
        optional_absent = sorted(absent & allowed)
        undocumented = set(got) - set(want)
        extra = sorted(undocumented - pending)       # emitted, not documented
        owed = sorted(undocumented & pending)
        submis = []
        for k in sorted(set(want) & set(got)):
            if want[k] and got[k] is not None:
                for m in sorted(want[k] - got[k]):
                    submis.append("%s.%s missing" % (k, m))
                for m in sorted(got[k] - want[k]):
                    submis.append("%s.%s undocumented" % (k, m))

        status = "OK" if not (missing or extra or submis) else "DRIFT"
        print("%-12s %-6s %s" % (ep, status, schema))
        for m in missing:
            print("    documented, not emitted : %s" % m); fail += 1
        for m in extra:
            print("    emitted, not documented : %s" % m); fail += 1
        for m in submis:
            print("    %s" % m); fail += 1
        for m in optional_absent:
            print("    (optional, absent)      : %s" % m)
        for m in owed:
            print("    (owed to the schema)    : %s" % m)

    print("\nRESULT:", "PASS" if fail == 0 else "FAIL (%d)" % fail)
    return 1 if fail else 0


# (dispatch is at the end of the file)


# ---------------------------------------------------------------------------
# Third leg: the markdown examples against the schema.
#
# The two checks above compare emitted-vs-spec. That misses the case where the
# human document promises a field neither the spec nor the code has -- which is
# exactly how `type`, `status`, `best_share` and `job` went unnoticed in the
# pool example. Run with --md to compare the markdown's JSON blocks too.

import re


def check_markdown(spec):
    """The markdown examples against the schema.

    The emitted-vs-spec checks above cannot see a field the human document
    promises that neither the spec nor the code has -- which is exactly how the
    pool example's type/status/best_share/job went unnoticed.
    """
    doc = open("docs/api-rest.md", encoding="utf-8").read()
    fail = 0
    # section -> (schema, the wrapper key the example nests its payload under)
    want = {"6.1": ("Summary", "summary"), "6.2": ("Thread", "threads"),
            "6.3": ("Device", "devices"), "6.4": ("System", "system"),
            "6.5": ("Pool", "pool")}
    for sec in sorted(want):
        schema, wrapper = want[sec]
        pat = "### %s .*?```json\n(.*?)```" % re.escape(sec)
        m = re.search(pat, doc, re.S)
        if not m:
            print("md %-4s SKIP (no example found)" % sec)
            continue
        keys = set(re.findall(r'"([a-z0-9_]+)"\s*:', m.group(1)))
        props = schema_props(spec, schema)
        props.pop("__required__", None)
        reachable = set(props)
        for sub in props.values():
            if sub:
                reachable |= sub          # $ref sub-objects resolved by schema_props
        reachable |= {"miner", wrapper}   # envelope and payload wrapper
        stray = sorted(keys - reachable)
        print("md %-4s %-6s %s" % (sec, "OK" if not stray else "DRIFT", schema))
        for k in stray:
            print("    example shows a field the schema does not define: %s" % k)
            fail += 1
    return fail


if __name__ == "__main__":
    if "--md" in sys.argv:
        _spec = yaml.safe_load(open(SPEC, encoding="utf-8"))
        _f = check_markdown(_spec)
        print("\nMARKDOWN:", "PASS" if _f == 0 else "FAIL (%d)" % _f)
        sys.exit(1 if _f else 0)
    sys.exit(main())
