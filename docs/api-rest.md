# Miner REST API -- contract v1

**Status: implemented by three miners.** No build promises to serve every route below, and two of
the three report the same `miner.kind`. Call `GET /api/v1/` and read the capability list rather than
assuming -- that is what it is for, and section 5 is the only place route availability is stated.

This document is the contract all three implementations are built against, and it was written before
any of them grew handlers: it is the interface an external manager, dashboard or monitoring agent
codes against, so it had to be agreed first.

This file is duplicated verbatim in all three miner trees, together with `openapi.yaml`. If you
change one copy, change all of them in the same session; keeping them identical is a maintainer
process and needs no action from a consumer of this document.

Examples below are normative for shape and field names. They are **real captured output** from a
running miner against a live pool, reformatted for width, with the operator's wallet replaced by
`wallet.worker`. Values are a snapshot, not a promise; field names and nullability are the contract.

---

## 1. Scope and versioning

Three miners implement one API:

| Miner | `miner.kind` | Devices | Pools |
|---|---|---|---|
| CUDA GPU miner | `gpu` | N CUDA GPUs, full NVML/NVAPI telemetry | pool array with failover |
| CPU miner | `cpu` | one CPU, temp/fan/clock | single pool |
| Vulkan GPU miner | `gpu` | N Vulkan devices of any vendor; telemetry only where the driver exposes it | single pool |

**No client may branch on which implementation it is talking to.** Everything a client needs is
keyed on `miner.kind` -- the only value it may branch on for the *shape of a payload* -- and on the
capability list of section 5. `miner.name` is a free-form identifier for logs and dashboards; it is
never part of a capability decision. Section 10 does name the implementations apart, in the few
places they genuinely differ; that is a description of the fleet for maintainers, never a
discriminator a client may reconstruct.

**Two implementations report `gpu` and they do not serve the same routes.** Which endpoints a build
serves is read from the capability list of section 5 and is never inferred from `miner.kind` --
section 10 describes field-level differences only, and says which implementations populate what.

**Identical paths, verbs, field names and error model on both.** Where one miner cannot serve a
resource it answers `501 not_implemented` on the same path rather than `404`, so a client never sees
a route appear or disappear -- only a capability flip. Section 5 says which routes a build serves;
section 10 lists the field-level differences between implementations.

Versioning: base path `/api/v1`. **Adding** a field, an endpoint or an enum value is not a breaking
change and does not bump the version -- clients must ignore unknown fields. Removing or retyping
anything bumps to `/api/v2`, and both versions would then be served during a deprecation window.
`miner.api_version` reports the contract revision (`"1.0"`), not the miner version.

## 2. Enabling it

| Option | Config key | Values | Default | Meaning |
|---|---|---|---|---|
| `--api-mode=MODE` | `"api-mode"` | `binary`, `http`, `both` | `binary` | protocol served on the API port |
| `--api-token=TOKEN` | `"api-token"` | string | none | require `Authorization: Bearer TOKEN` on **every** route |
| `--api-cors=ORIGIN` | `"api-cors"` | string | none | value for `Access-Control-Allow-Origin`; enables `OPTIONS` preflight |
| `--api-http-port=PORT` | `"api-http-port"` | int | `0` | with `both`: serve HTTP on a second port instead of sniffing one |
| `--api-control` | `"api-control"` | flag | off | enable `/api/v1/control/*`; without it those routes answer `403` |
| `--api-control-min-interval=S` | `"api-control-min-interval"` | int | `15` | minimum seconds between accepted control mutations |
| `--api-control-park-timeout=MS` | `"api-control-park-timeout"` | int | `30000` | how long a control call waits for mining threads to idle |

Modes:

- **`binary`** -- the historical `command|params` -> `KEY=value;...|` protocol only. Default, so an
  upgrade changes nothing.
- **`http`** -- the port speaks HTTP/JSON only. A binary command gets `400`. **This is the mode to
  use for remote control:** the legacy write verbs are unreachable and every route is token-gated.
- **`both`** -- one port, protocol decided from the first bytes of the connection. An uppercase
  ASCII token followed by a space is HTTP; anything else is a binary command. WebSocket upgrade
  requests keep working. Misdetection in either direction fails closed (no command executes).

Bind address and IP allowlisting are unchanged from each miner's binary API (`--api-bind` plus
whatever allowlist/permission flags it already has).

There is **no TLS in-process**. For anything beyond a trusted LAN, terminate TLS in nginx/caddy or
keep the rigs on WireGuard.

## 3. Conventions

- `Content-Type: application/json; charset=utf-8`, UTF-8, no BOM. Compact by default; `?pretty=1`
  indents.
- Every response body is a JSON **object**, never a bare array, so fields can be added later.
- Field names are `snake_case` with a **mandatory unit suffix**: `_hs` (hashes/second), `_khs`,
  `_mhz`, `_mw`, `_c` (Celsius), `_pct`, `_rpm`, `_ms`, `_s`, `_bytes`. Counters carry no suffix.
- **Unavailable values are `null`, never `0` and never omitted.** `0` means measured zero.
- Timestamps are unix seconds (integer). Durations end in `_s`.
- Trailing slashes are tolerated; unknown query parameters are ignored.
- `HEAD` is accepted wherever `GET` is. `OPTIONS` returns `204` + `Allow` when `--api-cors` is set.
  Another verb on a known path is `405` + `Allow`; an unknown path is `404`.
- Every response carries a `miner` object (section 5).
- **Units differ from the binary API on purpose:** JSON reports **H/s**, the binary API reported
  kH/s. The suffix makes it explicit; section 12 maps the old keys.

## 4. Authentication and privilege

Three privilege levels:

| Level | Requirement | Routes |
|---|---|---|
| `read` | source passes the IP allowlist; token if one is set | all `GET`, plus `/metrics` |
| `write` | `read` **plus** a privileged source (the miner's existing remote/admin permission flag) | `POST /pools/switch`, `/pools/url`, `/quit` |
| `control` | `write` **plus** `--api-control` | everything under `/control/` except `GET /control/state`, which is `read` |

**When `--api-token` is set it is required on every route, reads and `/metrics` included** -- there
is no exemption, because hashrate and pool identity are exactly what an intruder would want.
Missing or wrong token is `401` with `WWW-Authenticate: Bearer`, evaluated before routing or
privilege. Correct token from an unprivileged source is `403`.

```
Authorization: Bearer <token>
```

The token is matched **exactly**: `Bearer <token>trailing` is refused, not accepted as a prefix, and
a value longer than the miner accepts is refused rather than compared truncated.

**The legacy WebSocket compatibility path is covered by the token too.** That path lifts a command
out of the request URL, so without this it would reach the command table without the token check.
An upgrade request that does not carry a valid token is answered **`401`** and the connection is
closed; it is never upgraded and no command runs. It **answers rather than hanging up silently**,
because a client cannot tell silence from a network stall. Upgrade requests only -- a plain binary
command on the same port is the legacy protocol and is unaffected.

**The write flag is required for every caller, loopback included.** This API has no
local-machine exemption: without the miner's write flag a `POST` to a write or control route
answers `403 insufficient privilege` even from `127.0.0.1`, and `--api-control` alone is not
enough -- it upgrades an already-write-privileged caller to `control`, it does not grant write.
A `403` carrying `insufficient privilege` means the write flag is missing; the distinct message
`control API disabled (--api-control)` is the other case. Section 10 names each miner's flag.

Do not generalise from a miner's **legacy binary protocol**, which is a separate surface with
its own history and may exempt loopback there. It says nothing about this API.

Status codes, and the stable `error.code` that goes with each:

| Status | `code` | When |
|---|---|---|
| 400 | `bad_request` | malformed path, query or body; wrong JSON type; missing required field |
| 401 | `unauthorized` | missing/incorrect token |
| 403 | `forbidden` | unprivileged source, or `/control/*` without `--api-control` |
| 404 | `not_found` | unknown route, or index out of range |
| 405 | `method_not_allowed` | known path, wrong verb |
| 409 | `conflict` | a control mutation is already in progress, or one could not complete -- including a switch refused because the target algorithm's workspace does not fit in the memory available (section 7.5) |
| 413 | `payload_too_large` | body over 8 KiB |
| 429 | `too_many_requests` | control mutation inside `--api-control-min-interval` |
| 501 | `not_implemented` | this miner cannot serve this route |
| 500 | `internal_error` | handler failure |

Clients branch on `code`, never on the prose in `message`.

**A `429` carries `retry_after_s` in the error object** -- whole seconds, rounded **up**, so a client
that waits that long and retries is not throttled again. It is the only status that carries it, and
on a `429` it is always `>= 1`: never `0` and never `null`, because a refusal that says "come back in
no time" has told the caller nothing. Without it the delay would be readable only out of `message`,
which the rule above forbids.

Limits: request line <= 2 KiB, headers <= 8 KiB and <= 32 lines, body <= 8 KiB, socket timeout 5 s.
Responses are always `Connection: close` -- one request per connection, no keep-alive, no chunked
bodies, no compression.

## 5. Capability discovery -- call this first

`GET /api/v1/` is the only endpoint a client should hardcode. It reports which miner it is and
exactly which capabilities that build serves, so a manager negotiates once instead of probing for
`501`s.

```json
{
  "miner": { "name": "ccminer-tpfuemp", "version": "2026.07.2", "api_version": "1.0", "kind": "gpu" },
  "index": {
    "capabilities": ["summary", "threads", "devices", "system", "pools", "health",
                     "config", "algos", "history", "scanlog", "meminfo",
                     "pools.switch", "pools.url", "quit"],
    "links": { "summary": "/api/v1/summary", "devices": "/api/v1/devices" }
  }
}
```

**That capability list is one build's, not the contract's.** The example above omits the
`control.*` group and `metrics`; a build that does not route them answers `501` on those paths. A
routed `control.*` capability still answers `403` when the miner was started without
`--api-control`, so a manager should treat a `403` there as "control exists but is switched off",
not as a missing feature. A client must read the list rather than assume the full set -- that is the
whole point of calling this endpoint first.

The list is derived from the server's route table, so it cannot drift from what this build routes.
A capability absent here answers `501` if called. A routed `control.*` capability is listed even
when `--api-control` is off, and answers `403` in that case, as described above.

**Route availability is discovered here, per build -- never inferred from `miner.kind`.** Two
implementations can report the same kind and route different sets, so a client that branches on
`kind` to decide whether a path exists will be wrong on one of them. This is also what keeps the
cost of a fourth implementation flat: it publishes a capability list and adds no column anywhere.

`miner` is present on **every** response, including errors:

```json
{ "miner": { "name": "cpu-miner", "version": "3.2.1", "api_version": "1.0", "kind": "cpu" },
  "error": { "code": "not_implemented", "message": "scanlog is not available on this miner",
             "status": 501 } }
```

## 6. Endpoint reference

Every path the contract defines, with the capability string that announces it. **This table is the
inventory, not an availability list**: whether a given build serves a path is read from that build's
capability list (section 5), and a path whose capability is absent answers `501`. `Priv` is the
privilege the caller needs -- section 4.

| Method | Path | Priv | Capability |
|---|---|---|---|
| GET | `/api/v1/` | read | *(always served)* |
| GET | `/api/v1/summary` | read | `summary` |
| GET | `/api/v1/threads` | read | `threads` |
| GET | `/api/v1/devices`, `/devices/{id}` | read | `devices` |
| GET | `/api/v1/system` | read | `system` |
| GET | `/api/v1/pools`, `/pools/{n}` | read | `pools` |
| GET | `/api/v1/health` | read | `health` |
| GET | `/api/v1/history` | read | `history` |
| GET | `/api/v1/scanlog` | read | `scanlog` |
| GET | `/api/v1/meminfo` | read | `meminfo` |
| GET | `/api/v1/config` | read | `config` |
| GET | `/api/v1/algos` | read | `algos` |
| POST | `/api/v1/pools/switch` | write | `pools.switch` |
| POST | `/api/v1/pools/url` | write | `pools.url` |
| POST | `/api/v1/quit` | write | `quit` |
| GET | `/api/v1/control/state` | read | `control.state` |
| POST | `/api/v1/control/start`, `/pause`, `/stop` | control | `control.start`, `.pause`, `.stop` |
| POST | `/api/v1/control/profile` | control | `control.profile` |
| GET | `/metrics` | read | `metrics` |

Two shape notes that are not availability: a miner with one device serves `/devices` as a
one-element array, and a single-pool miner serves `/pools` as one element and accepts index `0`
only. Both are section 10 rows.

Query parameters: `/threads?id=N`, `/history?thread=N&limit=50` (capped at 50) ,
`/pools?index=N` (alias for `/pools/{n}`), `?pretty=1` everywhere.

### 6.1 `GET /api/v1/summary`

```json
{ "miner": { "...": "" },
  "summary": {
    "algo": "sha3t",
    "uptime_s": 40,
    "timestamp": 1786735914,
    "hashrate_hs": 269024983.0,
    "hashrate_avg_hs": null,
    "devices": 1,
    "threads": 1,
    "shares": { "accepted": 5, "rejected": 0, "stale": null, "solved": 0, "accepted_per_min": 7.5 },
    "difficulty": { "pool": 1.0, "network": 372.6308775514737, "best_share": 8.176620023103917 },
    "network": { "hashrate_hs": null },
    "pools": { "count": 1, "active": 0, "wait_time_s": 1 } } }
```

`hashrate_avg_hs` is `null` because this build does not track a rolling average yet, and
`shares.stale` is `null` because stale counts are per pool -- see `/pools`. Both are the `null`
convention doing its job: the value is unavailable, not zero.

`devices` is the GPU count when `kind` is `gpu`, the CPU count when it is `cpu`. Errors: `401`, `403`, `500`.

**A hashrate is a measurement, so a miner that is not hashing reports `0`, not its last value.**
That covers `/summary`, `/threads`, `/devices` and the metrics gauges, and it applies while the
control API holds the miner `paused` or `stopped`. Past rates remain available from `/history`.
`0` therefore means "not hashing now" and never "broken" -- read `/control/state` or
`miner_control_state` to learn which.

### 6.2 `GET /api/v1/threads`

`{"threads":[...]}`, one entry per mining thread:

```json
{ "id": 0, "device_id": 0, "hashrate_hs": 269024982.6536372,
  "accepted": 5, "rejected": 0, "hw_errors": 0,
  "intensity": 25.0, "throughput": 33554432 }
```

`intensity` and `throughput` are `null` on a `cpu` miner, as are `accepted`/`rejected` until it
grows per-thread accounting. `device_id` indexes into `/devices`.

### 6.3 `GET /api/v1/devices`, `GET /api/v1/devices/{id}`

`{"devices":[...]}` -- a common shell plus a typed sub-object naming the device class, and on one
implementation a second naming the compute stack:

```json
{ "id": 0, "type": "gpu", "name": "NVIDIA GeForce RTX 3060",
  "temp_c": 74.0, "fan_pct": 46, "fan_rpm": null,
  "clock_mhz": null, "mem_clock_mhz": null,
  "power_mw": 145470, "power_limit_mw": 170000,
  "hashrate_hs": 269024982.6536372, "hashrate_per_watt_khs": null,
  "gpu": { "bus_id": 1, "sm": 860, "mem_bytes": 12884901888, "pstate": "P2",
           "base_clock_mhz": 1777, "base_mem_clock_mhz": 7501,
           "vendor_id": "0x103c", "device_id": "0x8903",
           "serial": "C445A31728", "bios": "94.06.2f.00.ed",
           "nvml_id": 0, "nvapi_id": 0, "monitoring": true } }
```

`clock_mhz`, `mem_clock_mhz`, `fan_rpm` and `hashrate_per_watt_khs` are `null` above because they
come from the optional monitoring sampler, which was not running in that capture. `sm` is the compute
capability x10 (860 = 8.6), not x1.

A `cpu` miner emits one `"type": "cpu"` entry with a `cpu` sub-object (`cores`, `threads`,
`features`) and no `gpu` key. **Clients must tolerate any sub-object being absent.** `features`
is an **array of strings** (`["AES", "SHA256", "NEON"]`), never a delimited string, and `null` when
the miner cannot determine the instruction set.

A Vulkan `gpu` miner emits the `gpu` sub-object with most members `null` -- a portable device layer
reads no vendor telemetry -- and **a `vulkan` sub-object beside it**:

```json
  "vulkan": { "driver": "595.95", "api_version": "1.4.329", "backend": "vulkan",
              "int64": true, "tuned": true, "workgroup": 1024, "queue_depth": 3,
              "kernel": "spec-sub", "batches_total": 1774, "batches_late": 56,
              "shared_table_bytes": 1123123200 }
```

`workgroup`, `queue_depth` and `kernel` are the tuning settled for that device and are `null` until
a tuning pass has run; they are per-device measurements, not properties of the algorithm.
`batches_total` and `batches_late` are process-lifetime counters, a late batch being one whose
result arrived after its job had moved on. `shared_table_bytes` is the epoch-scoped table the
device is holding right now -- a DAG or similar -- and is `null` when it holds none, never `0`: a
table of no size is not a thing this reports. It is what makes section 7's retained-across-`pause`
allowance observable rather than inferred, so a manager weighing `pause` against `stop` can read
what a `pause` would keep. The sub-object is additive, so a client that does not
know it ignores it -- section 1's versioning rule.

This is the **expensive** route -- it queries the vendor telemetry libraries. Poll `/summary` or
`/health` instead if you only need rates. `404` for an unknown `{id}`.

### 6.4 `GET /api/v1/system`

```json
{ "os": "windows", "driver": "595.95", "cpus": 16, "cpu_temp_c": null,
  "cpu_clock_mhz": null, "cpu_fan_pct": null }
```

`driver` is the GPU driver version on a `gpu` miner, `null` on a `cpu` miner.

### 6.5 `GET /api/v1/pools`, `GET /api/v1/pools/{n}`

```json
{ "index": 0, "active": true, "name": "pool1",
  "url": "stratum+tcp://host:3333", "user": "wallet.worker",
  "algo": "x16r", "type": "stratum", "status": "connected",
  "shares": { "accepted": 41, "rejected": 1, "stale": 0, "solved": 0 },
  "difficulty": 0.5, "best_share": 3.21,
  "job": { "id": "6a1f", "height": 812345, "extranonce2_size": 4, "extranonce2": "0x00000000" },
  "ping_ms": 42, "disconnects": 0, "wait_time_s": 12, "session_s": 3600, "last_share_age_s": 8 }
```

`user` is exposed as the binary API already exposes it (stratum only); the **password is never
returned by any endpoint**. A `cpu` miner's array always has length 1, so only index `0` exists.

### 6.6 `GET /api/v1/health`

Cheap enough to poll every 5 s -- no vendor telemetry calls.

```json
{ "status": "ok", "mining": true, "pool_connected": true, "devices_ok": 1 }
```

`200` when healthy; `503` with `"status": "degraded"` and `"reasons": ["pool_disconnected"]`
otherwise. **A deliberately stopped miner is `200 ok` with `"mining": false`** -- a manager-initiated
stop is not a fault. Ask `/control/state` for *why* mining is off.

### 6.7 `GET /api/v1/history`, `/scanlog`, `/meminfo`

`history` returns the last 50 scan records per worker. `scanlog` and `meminfo` both describe a hash
log -- a per-job record of scanned nonce ranges, kept for resume and dedup -- so a miner that gives
its workers disjoint ranges by construction keeps no such log and answers `501` permanently. Read
the capability list to find out; `scanlog` is additionally debug-build-only where it is served, and
`meminfo` reports the miner's own bookkeeping allocations.

### 6.8 `GET /api/v1/config`

Effective options after config file + command line, **with credentials masked** (`user`, `pass`, and
any userinfo inside a URL). Use it to confirm what a rig is actually running.

**Its key set mirrors each miner's own options, so unlike every other response body it is not
identical across miners** -- and not across two miners of the same `kind` either: the CUDA miner
exports `intensity`, the Vulkan one exports its own tuning keys, the CPU one neither. Read the keys
that are present rather than expecting a fixed shape, and do not treat a missing key as an error.
This is the one documented exception to section 10's "everything else is identical".

### 6.9 `GET /api/v1/algos`

The authoritative, machine-readable list of algorithms this build can switch to, and which
parameters each one accepts:

```json
{ "algos": [
  { "name": "x16r", "params": [] },
  { "name": "yescrypt", "params": [
      { "name": "n",   "type": "int",    "tier": "fast" },
      { "name": "r",   "type": "int",    "tier": "fast" },
      { "name": "key", "type": "string", "tier": "fast" } ] },
  { "name": "verthash", "params": [
      { "name": "data_file", "type": "string", "tier": "slow" } ] } ] }
```

**Do not hardcode this list.** It differs between implementations and between builds of one;
section 9 explains the parameter tiers.

### 6.10 Write endpoints

All take a JSON body and answer `200 {"result":{...}}`.

- **`POST /api/v1/pools/switch`** -- `{"index": 1}` or `{"next": true}` -> `{"ok":true,"active":1}`.
  Out-of-range index -> `404`. A miner with no pool array does not serve this at all: pool selection
  belongs to the manager, which supplies a pool with every `/control/profile` call.
- **`POST /api/v1/pools/url`** -- `{"url":"stratum+tcp://host:port","user":"...","pass":"x"}`;
  `user`/`pass` optional. The handler assembles whatever internal form the miner needs, so clients
  never build a packed string.
- **`POST /api/v1/quit`** -- terminates the **process**. The `200 {"ok":true}` is flushed before the
  shutdown flag is acted on. This is not a stop verb: nothing can restart the miner afterwards. Use
  `/control/stop` for a reversible stop.

## 7. Control API

Off unless `--api-control` is given. Designed for a profit-switching manager: it can stop, start and
re-target the miner without restarting the process.

### 7.1 State machine

Four states. Every mutation passes through `switching` and lands in exactly one of the other three.

| from (row) / verb (column) | `start` | `pause` | `stop` | `profile` |
|---|---|---|---|---|
| `running` | no-op `200` | -> `paused` | -> `stopped` | -> the profile's `run` target |
| `paused` | -> `running` | no-op `200` | -> `stopped` (drops connection) | applies, then honours `run` (default: stay `paused`) |
| `stopped` | -> `running` (reconnects first) | -> `paused` (reconnects, stays parked) | no-op `200` | applies, then honours `run` (default: stay `stopped`) |
| `switching` | `409 conflict` | `409 conflict` | `409 conflict` | `409 conflict` |

- **No-ops return `200` and do not advance `epoch`.** A manager can therefore be crash-safe by
  simply re-asserting the state it wants instead of tracking what it last sent.
- **`pause` vs `stop`** differ in exactly one respect: `stop` also drops the pool connection.
  Both release device resources and keep the process and API alive.

| | process | API answers | device resources | pool connection | counted as a pool disconnect |
|---|---|---|---|---|---|
| `pause` | alive | yes | freed, but see below | **kept alive** | no |
| `stop` | alive | yes | freed | **dropped** | **no** (deliberate stops are not pool faults) |
| `quit` | exits | no | freed | dropped | n/a |

- **An implementation may retain a large epoch-scoped dataset across a `pause`** -- a DAG or a
  similar shared table -- rather than free it and rebuild it on resume. The guarantee `pause` makes
  is that no work continues and no share is produced, not that every allocation is returned; the
  observable consequences are a fast resume and memory still accounted to the process. A manager
  that needs the memory back issues `stop`, or `quit`. Where an implementation retains such a
  table it reports the amount rather than leaving it to be inferred from the process: on the
  Vulkan miner that is `devices[].vulkan.shared_table_bytes`, `null` on a device holding nothing.
- Mutations are serialised. A second one arriving during `switching` gets `409`, never a queue.
- Mutations are throttled to one per `--api-control-min-interval` (default 15 s); a faster call gets
  `429`, whose error object carries `retry_after_s` -- how long is left, so the caller waits that
  long rather than guessing. `start`/`pause`/`stop` are **not** throttled, only re-targeting is.

Internally a mutation parks every mining thread first and only then changes anything, so an algo
switch can never race a running kernel. If a thread does not park within
`--api-control-park-timeout`, the mutation is **abandoned and rolled back** (`409`, with the reason
in `last_error`) rather than forced.

### 7.2 `GET /api/v1/control/state`

Read privilege -- a manager is expected to poll this.

```json
{ "control": {
    "state": "running",
    "epoch": 42,
    "since_s": 118,
    "algo": "x16rv2",
    "params": { "n": null, "r": null, "key": null },
    "pool": { "index": 0, "url": "stratum+tcp://host:3333", "user": "wallet.worker" },
    "pool_connected": true,
    "threads_total": 3, "threads_parked": 0,
    "switch_count": 7, "last_switch_age_s": 118,
    "min_interval_s": 15, "ready_for_switch": true,
    "last_error": null } }
```

`epoch` increments once per accepted mutation and is the reliable way to tell "my change took
effect" from "the state happens to look right". `pool_connected` is `null` for getwork/GBT.
`ready_for_switch` is `false` while the anti-flap interval is unexpired -- check it to avoid a `429`.

### 7.3 `POST /api/v1/control/pause`, `/stop`, `/start`

Body `{"wait_ms": 10000}`, optional. Responses carry the resulting state:

```json
{ "result": { "state": "paused", "epoch": 43, "parked": 3 } }
```

`start` from `stopped` reconnects, re-subscribes and re-authorises, so it takes seconds and **can
fail** -- the state returns to `stopped`, `last_error` is set and `epoch` does not advance. All three
verbs return when the state flag is set, **not** when hashing has ramped up; confirm throughput via
`/summary.hashrate_hs`.

### 7.4 `POST /api/v1/control/profile` -- the endpoint a manager should use

One atomic change of algorithm, parameters, pool and run state:

```json
{ "algo": "x16rv2",
  "params": { "n": 2048, "key": "Client Key" },
  "pool": { "url": "stratum+tcp://host:port", "user": "wallet.worker", "pass": "x" },
  "run": true,
  "wait_ms": 10000 }
```

Sequence: park once -> apply algo and params -> apply pool -> set run state -> one `epoch++` -> respond
with the resulting `/control/state` body. **If any step fails, all of them are rolled back** to the
pre-call algo/params/pool and the response is `409` with `last_error`. A half-switched miner is never
a possible outcome.

**`algo` and `pool` must be sent together.** An `algo` without a `pool` is `400`, not a best-effort
switch: mining algorithm X against a pool expecting Y produces 100 % rejected shares while every
other metric looks healthy. That is also why there is no `/control/algo` endpoint -- the invariant is
structural rather than merely validated.

Legal bodies: `algo`+`pool` (+/- `params`, `run`) for a full switch; `pool` alone to re-target the
same algorithm; `params` alone to retune the current algorithm; `run` alone as a synonym for
`start`/`pause`.

### 7.5 Memory-hungry algorithms are refused, not attempted

A switch whose target needs more memory than is available is rejected with `409` and a `last_error`
naming the arithmetic, rather than attempted and left to fail:

```
equihash144 needs 24.3 GB for 8 threads (3106 MB each) but only 14.0 GB is free
-- 3 thread(s) would fit. Restart with -t 3 to mine it here.
```

The check runs after the target algorithm registers -- its workspace is sized from the parameters
read at registration, so it is not knowable earlier -- and before any thread allocates. Threads are
parked and the previous algorithm is restored, so a refusal costs a brief pause and nothing else.

The worker count cannot be lowered to fit: workers are parked for a switch, not destroyed, so their
number is a property of the process. **A manager that wants a high-memory algorithm on a small
machine must start the miner sized for it** -- or run one miner process per algorithm class. The
refusal exists because the alternative is not a failed allocation but an OOM kill: the workspaces
are touched, so overcommit cannot absorb them, and the kernel takes the whole process down along
with its session stats and any queued shares.

NOTE: this is the one control-path failure a manager cannot retry its way out of. Treat a `409`
mentioning `needs ... GB` as permanent for that combination of algorithm, parameters and worker count.

**Availability:** per implementation, not per kind -- see section 10. The refusal above is the CPU
miner's, and its arithmetic is worker workspaces against system memory. The two `gpu` miners differ
from each other here: one performs an equivalent pre-check over *device* memory and one performs
none, so a client cannot infer the behaviour from `miner.kind` and can only observe the `409`.
Where the check is performed at all the shape is identical -- `409`, a `last_error` naming the
arithmetic, threads parked and the previous algorithm restored.

### 7.6 Worked profit-switch sequence

```
GET  /api/v1/                     -> capabilities; confirm "control.profile" is present
GET  /api/v1/summary              -> current algo + hashrate for the profitability model
POST /api/v1/control/profile      -> {"algo":"...","pool":{...},"params":{...},"run":true}
GET  /api/v1/control/state        -> poll until state == "running" and epoch has advanced
GET  /api/v1/summary              -> confirm hashrate recovered for the new algo
GET  /api/v1/pools/0              -> confirm shares are being ACCEPTED, not just submitted
```

The last step matters: a `200` from `/control/profile` proves the switch was applied, not that the
pool agrees with your algorithm choice.

**Slow parameters** (section 9) cannot complete inside a request. If the change needs longer than
`wait_ms`, the response is `202 Accepted` with the current state; poll `/control/state` until
`epoch` advances (success) or `last_error` is populated (failure, previous configuration still
running). Setting `wait_ms: 0` always takes this path.

## 8. Field dictionary

One alphabetical table so a name cannot mean two things in two places. `n` = nullable.

| Field | Type | Unit | n | Meaning |
|---|---|---|---|---|
| `accepted` | int | -- | yes | accepted shares (scope: summary, thread, pool) |
| `accepted_per_min` | float | 1/min | | accepted shares per minute, process lifetime |
| `active` | bool | -- | | this pool is the one currently mined |
| `algo` | string | -- | | algorithm name as accepted by `--algo` |
| `api_version` | string | -- | | top level: contract revision, `"1.0"`. In the `vulkan` sub-object: the Vulkan API level the device reports, e.g. `"1.4.329"` |
| `backend` | string | -- | yes | compute backend a device is driven through, e.g. `"vulkan"` |
| `base_clock_mhz` | int | MHz | yes | stock core clock |
| `batches_late` | int | -- | yes | dispatches whose result arrived after the job had moved on |
| `batches_total` | int | -- | yes | dispatches issued to this device since process start |
| `best_share` | float | difficulty | yes | best share difficulty seen |
| `bios` | string | -- | yes | GPU VBIOS version |
| `bus_id` | int | -- | yes | PCI bus id |
| `capabilities` | array | -- | | capability strings served by this build |
| `clock_mhz` | int | MHz | yes | current core clock |
| `code` | string | -- | | stable machine-readable error code |
| `cores` | int | -- | yes | physical CPU cores |
| `cpu_clock_mhz` | int | MHz | yes | CPU clock |
| `cpu_temp_c` | float | C | yes | CPU temperature |
| `cpus` | int | -- | yes | logical CPUs |
| `device_id` | int/string | -- | yes | thread->device index; in `gpu` sub-object, the PCI device id |
| `devices` | int/array | -- | | count in `summary`, array at `/devices` |
| `devices_ok` | int | -- | | devices reporting healthy |
| `difficulty` | float/object | difficulty | | pool difficulty (pool scope) or `{pool,network,best_share}` |
| `disconnects` | int | -- | | **unintentional** pool disconnects only |
| `driver` | string | -- | yes | GPU driver version |
| `epoch` | int | -- | | increments once per accepted control mutation |
| `extranonce2` / `extranonce2_size` | string/int | -- | yes | stratum job fields |
| `fan_pct` / `fan_rpm` | int | % / rpm | yes | fan speed |
| `features` | array | -- | yes | CPU instruction-set features |
| `hashrate_avg_hs` | float | H/s | | session-average hashrate |
| `hashrate_hs` | float | H/s | | current hashrate; **`0` whenever the miner is not hashing**, including while paused or stopped by the control API |
| `hashrate_per_watt_khs` | float | kH/s/W | yes | efficiency |
| `health.status` | string | -- | | `ok` \| `degraded` |
| `height` | int | -- | yes | block height of the current job |
| `hw_errors` | int | -- | yes | hardware/validation errors on this thread |
| `id` | int | -- | | device or thread index |
| `index` | int | -- | | pool index |
| `int64` | bool | -- | yes | device advertises 64-bit integer support in shaders |
| `intensity` | float | -- | yes | GPU launch intensity |
| `job.id` | string | -- | yes | stratum job id |
| `kernel` | string | -- | yes | kernel variant the tuner selected for this device; `null` until tuned |
| `kind` | string | -- | | `gpu` \| `cpu`. **Two implementations report `gpu`**; see section 10 |
| `last_error` | string | -- | yes | reason the last control mutation failed |
| `last_share_age_s` | int | s | yes | seconds since the last accepted share |
| `last_switch_age_s` | int | s | yes | seconds since the last control mutation |
| `mem_bytes` | int | bytes | yes | device memory |
| `mem_clock_mhz` | int | MHz | yes | memory clock |
| `min_interval_s` | int | s | | configured anti-flap interval |
| `mining` | bool | -- | | is the miner hashing right now |
| `monitoring` | bool | -- | | telemetry available for this device |
| `name` | string | -- | | miner name, device name or pool name by scope |
| `network.hashrate_hs` | float | H/s | yes | network hashrate |
| `params` | object | -- | yes | algorithm parameters in effect; `null` members = not set |
| `parked` / `threads_parked` | int | -- | | mining threads currently idle |
| `ping_ms` | int | ms | yes | pool round-trip time |
| `pool_connected` | bool | -- | yes | `null` for getwork/GBT |
| `power_mw` / `power_limit_mw` | int | mW | yes | power draw and cap |
| `pstate` | string | -- | yes | performance state |
| `queue_depth` | int | -- | yes | dispatches kept in flight on this device; `null` until tuned |
| `ready_for_switch` | bool | -- | | anti-flap interval has expired |
| `reasons` | array | -- | yes | why health is `degraded` |
| `rejected` | int | -- | yes | rejected shares |
| `retry_after_s` | int | s | | **error scope, `429` only**: whole seconds to wait before retrying, rounded up; always `>= 1` |
| `serial` | string | -- | yes | device serial |
| `session_s` | int | s | yes | **pool scope**: seconds since the current pool connection was established, reset by a reconnect. `null` when this pool is not connected. Read `uptime_s` for the process |
| `shared_table_bytes` | int | bytes | yes | epoch-scoped table (a DAG or similar) this device is holding; `null` when it holds none. Survives a `pause` -- section 7 |
| `shares` | object | -- | | `{accepted,rejected,stale,solved[,accepted_per_min]}` |
| `since_s` | int | s | | seconds in the current control state |
| `sm` | int | -- | yes | CUDA compute capability x10 |
| `solved` | int | -- | | blocks solved |
| `stale` | int | -- | yes | stale shares |
| `state` | string | -- | | `running` \| `paused` \| `stopped` \| `switching` |
| `status` | string | -- | | pool connection status |
| `switch_count` | int | -- | | accepted control mutations this session |
| `temp_c` | float | C | yes | device temperature |
| `threads` | int/array | -- | | count in `summary`, array at `/threads` |
| `threads_total` | int | -- | | configured mining threads |
| `throughput` | int | -- | yes | nonces per launch |
| `timestamp` | int | unix s | | when the response was generated |
| `tuned` | bool | -- | yes | a tuning pass has settled for this device |
| `type` | string | -- | | `gpu` \| `cpu` (device), `stratum` \| `getwork` (pool) |
| `uptime_s` | int | s | | **process uptime**, at every scope it appears. Never a pool session length -- that is `session_s` |
| `url` | string | -- | | pool URL, never containing a password |
| `user` | string | -- | yes | pool username/wallet |
| `vendor_id` | string | -- | yes | PCI vendor id |
| `version` | string | -- | | miner version |
| `wait_time_s` | int | s | yes | time spent waiting for work |
| `workgroup` | int | -- | yes | settled local workgroup size for this device; `null` until tuned |

## 9. Algorithm parameters

Some algorithms take parameters beyond their name (`n`, `r`, `key`, a data file, ...). The contract:

- **`GET /api/v1/algos` is authoritative.** It lists, per algorithm, the accepted parameter names,
  their types and their tier. Managers must read it rather than hardcoding, because the set differs
  between the two miners and between builds. A parameter absent from an algorithm's list is
  **rejected** for that algorithm, not ignored -- an algorithm that would silently drop a parameter
  is the one case a profit switcher cannot detect, because the miner then hashes the wrong thing at
  the right rate.
- **Types** are `int`, `string`, `int_list` and `float_list`. The two list types are
  comma-separated and positional, one entry per device; a single value applies to every device.
  Values are range-checked before anything is applied.
- Parameters are applied **live** -- no process restart. They are validated per algorithm; an unknown
  name, a wrong type or an out-of-range value is `400` and **nothing** is applied.
- **Omitted != `null`.** Omitting a parameter keeps the value currently in effect; sending `null`
  resets it to the algorithm's default.
- Parameters are **sticky per algorithm**: switching away and back restores what you last set for
  that algorithm.
- **Two tiers.** `fast` parameters take effect within the park window like an algorithm switch.
  `slow` parameters need file or network I/O (`data_file` for verthash, `scratchpad_url` for
  wildkeccak) and take seconds to minutes; those return `202` and are polled (section 7.6). Failure
  leaves the previous configuration running and populates `last_error`.
- A parameter accepted by one implementation and not another is listed in section 10.

## 10. Differences by implementation

**Route availability is not in this table.** It is read from the capability list of section 5, per
build. Two implementations report the same `kind` and do not serve the same routes, so no static
table keyed on `kind` can state which paths exist without going stale -- which is what this table
used to do, and what it no longer attempts.

What remains is field-level: which implementations populate a field, and where a gate or a refusal
differs. The two `gpu` miners are named apart in the columns **only** where they differ; a client
still branches on the capability list and on `kind`, never on a column heading.

| Path / field | `gpu` CUDA | `gpu` Vulkan | `cpu` | Why |
|---|---|---|---|---|
| `/pools` array length | `0..n` | always `1` | always `1` | only the CUDA miner carries a pool array with failover |
| `threads[].accepted` / `.rejected` | yes | yes | yes | on `cpu`, `null` until that worker has had a share attributed to it |
| `threads[].hw_errors` | device hardware/validation errors | **candidates the host refused** -- not a hardware counter | `null` | the Vulkan miner re-hashes every candidate on the host before submitting it, so its counter means *the device disagreed with the CPU reference*. Non-zero is a correctness signal, not a failing card |
| `threads[].intensity` / `.throughput` | yes | `null` | `null` | launch concepts the Vulkan miner does not express; its per-device tuning lives in `devices[].vulkan` |
| `summary.shares.stale` | `null` -- counted per pool, read `/pools/{n}` | populated | populated | two of the three keep a process-wide counter and report it in both places. **A client that skips `/pools/{n}` because `kind == "gpu"` promised `null` will miss a populated field on one of them** |
| `devices[].gpu` | present | present, mostly `null` | absent | a portable device layer reads no vendor telemetry |
| `devices[].vulkan` | absent | **present** | absent | backend, driver, API level, settled tuning and batch counters -- section 6.3 |
| `devices[].cpu` | absent | absent | present | -- |
| `system.driver` | yes | yes | `null` | no GPU driver |
| memory pre-check on switch (section 7.5) | none | over device memory | over system memory | **the row `kind` genuinely cannot carry**: the two `gpu` miners differ from each other, so a client observes the `409` and never infers it |
| Write gate | group `W` via `--api-allow` | `--api-remote` | `--api-remote` | different pre-existing option models, each unchanged by this API. Keyed on the implementation rather than on `kind`, and it is **operator documentation, not a capability**: a client only ever sees `403`, and section 1 forbids branching on `name` |
| Write gate, **remote** caller | requires `W:` in `--api-allow`, or a custom group whose command list names the command | requires `--api-remote` | requires `--api-remote` | on the CUDA miner the `R:`/`W:` distinction is enforced on **every** protocol on the port, not only on REST |
| Write gate, **loopback** caller | same as a remote caller | same as a remote caller | same as a remote caller | **no implementation exempts loopback on this API.** The CUDA miner exempts it on its legacy binary protocol only |
| `POST /pools/url` | write gate only | **write gate *and* `--api-control`** | write gate only | on the Vulkan miner a re-target runs under the same park barrier a control mutation uses, and with the control API off that barrier is compiled out to a constant. Serving it without the flag would mean building a second, unparked re-target path; refusing is the safer of the two, and a `pool`-only `/control/profile` is the same operation behind the gate that documents it |

Out of scope for v1 on all three miners, stated so it is not mistaken for an omission: no process
restart or self-update, no overclock/fan/power control, no profitability logic inside the miner, no
pool inventory management, no push/streaming (the API is strictly pull), no TLS in-process.

## 11. Metrics

`GET /metrics` -- Prometheus text exposition, deliberately **outside** `/api/v1/` because it is not
versioned JSON and scrapers default to that path. Read privilege; the token applies if set.
`Content-Type: text/plain; version=0.0.4; charset=utf-8`. Base units (seconds, watts), `_total` on
counters, `# HELP`/`# TYPE` on every family. No self-reported `up` metric -- Prometheus synthesises
that from the scrape.

| Metric | Type | Labels | Unit |
|---|---|---|---|
| `miner_hashrate_hashes_per_second` | gauge | `algo` | H/s |
| `miner_device_hashrate_hashes_per_second` | gauge | `device`, `type`, `algo` | H/s |
| `miner_network_difficulty`, `miner_pool_difficulty` | gauge | -- | difficulty |
| `miner_shares_total` | counter | `result="accepted\|rejected\|stale"` | shares |
| `miner_blocks_solved_total` | counter | -- | blocks |
| `miner_pool_disconnects_total` | counter | `pool` | disconnects (**unintentional only**) |
| `miner_pool_last_share_age_seconds` | gauge | `pool` | s |
| `miner_pool_connected` | gauge 0/1 | `pool` | -- (absent for getwork/GBT) |
| `miner_mining_active` | gauge 0/1 | -- | -- |
| `miner_control_state` | gauge 0/1 | `state="running\|paused\|stopped\|switching"` | -- (exactly one series is 1) |
| `miner_uptime_seconds` | gauge | -- | s |
| `miner_info` | gauge (always 1) | `version`, `algo`, `kind`, `name` | -- |
| `miner_device_temperature_celsius` | gauge | `device` | C |
| `miner_device_power_watts` | gauge | `device` | W |
| `miner_device_fan_percent` | gauge | `device` | % |
| `miner_device_hw_errors_total` | counter | `device` | errors |
| `miner_device_batches_total` | counter | `device` | batches |
| `miner_device_batches_late_total` | counter | `device` | batches |
| `miner_host_disagreements_total` | counter | `reason="below_target\|wrong_digest"` | candidates |

`miner_shares_total` is **process-lifetime monotonic**: the metrics layer keeps its own accumulating
totals, because some internal counters are reset on an algorithm switch and a counter that decreases
corrupts `rate()`.

The last three families are published by the Vulkan miner only. **`miner_host_disagreements_total`
is deliberately not labelled by device**, where every other device family is: a candidate the host
refused is counted for the process, and attributing it to a card would be inventing a number on any
rig with more than one. Read it as a correctness signal -- a non-zero `wrong_digest` means a device
returned a hash the host could not reproduce, and `below_target` a candidate that did not survive
the full-width compare -- and read `miner_device_hw_errors_total` as the per-device hardware counter
it is on the implementations that have one. The two are not substitutes for each other.

**A series is absent rather than zero when the miner has no value for it** -- the same rule the JSON
side expresses as `null`, because Prometheus has no null and a fabricated `0` poisons every average
built on it. Concretely: device temperature, power and fan are published only where the miner's
telemetry sampler has a reading (a miner started quiet, or without vendor telemetry, reports
hashrate but no temperature), and `miner_pool_connected` is published only for a pool that can
actually hold a connection -- a stratum pool the miner is currently using. A miner keeping one live
socket therefore exports one `miner_pool_connected` series, not one per configured pool.

`miner_network_difficulty` and `miner_pool_difficulty` follow the same rule and are **header-only
until the miner has a value**: a benchmark run has no chain, and a fresh connection has no pool
difficulty until the pool sets one. `0` is a difficulty no chain has, so publishing it would be a
fabrication that every average built on the series would inherit.

Scrape config:

```yaml
scrape_configs:
  - job_name: miners
    scrape_interval: 30s
    authorization:
      credentials: <the --api-token value>
    static_configs:
      - targets: ['rig1:4068', 'rig2:4068']
```

Worked queries -- these three are why the endpoint exists:

```promql
# unintended downtime only: ignores manager-initiated stops
miner_mining_active == 0
  unless on(instance) miner_control_state{state=~"stopped|paused|switching"} == 1

# reject rate over 15 minutes, as pool health
sum(rate(miner_shares_total{result="rejected"}[15m]))
  / sum(rate(miner_shares_total[15m])) > 0.02

# effective hashrate per algorithm, for the profitability model
sum by (algo) (miner_hashrate_hashes_per_second)
```

## 12. Migration from the binary API

The binary protocol is unchanged and stays the default. Mapping for existing consumers:

| Binary | REST |
|---|---|
| `summary` -> `KHS` | `/summary` -> `hashrate_hs` (**H/s, not kH/s**) |
| `summary` -> `ACC`, `REJ`, `ACCMN`, `SOLV` | `/summary` -> `shares.accepted`, `.rejected`, `.accepted_per_min`, `.solved` |
| `summary` -> `DIFF`, `NETKHS` | `/summary` -> `difficulty.network`, `network.hashrate_hs` |
| `summary` -> `UPTIME`, `TS` | `/summary` -> `uptime_s`, `timestamp` |
| `threads` -> `GPU`, `KHS`, `HWF`, `I`, `THR` | `/threads[]` -> `device_id`, `hashrate_hs`, `hw_errors`, `intensity`, `throughput` |
| `hwinfo` -> `TEMP`, `FAN`, `RPM`, `POWER`, `PLIM` | `/devices[]` -> `temp_c`, `fan_pct`, `fan_rpm`, `power_mw`, `power_limit_mw` |
| `hwinfo` -> `FREQ`, `MEMFREQ` (base) | `/devices[]` -> `gpu.base_clock_mhz`, `gpu.base_mem_clock_mhz` |
| `hwinfo` -> `GPUF`, `MEMF` (current) | `/devices[]` -> `clock_mhz`, `mem_clock_mhz` |
| `hwinfo` -> `SM`, `MEM`, `PST`, `VID`, `PID`, `SN`, `BIOS` | `/devices[]` -> `gpu.sm`, `gpu.mem_bytes` (**bytes, not MB**), `gpu.pstate`, `gpu.vendor_id`, `gpu.device_id`, `gpu.serial`, `gpu.bios` |
| `hwinfo` -> `OS`, `NVDRIVER`, `CPUS`, `CPUTEMP`, `CPUFREQ` | `/system` -> `os`, `driver`, `cpus`, `cpu_temp_c`, `cpu_clock_mhz` |
| `pool` -> `POOL`, `URL`, `USER`, `DIFF`, `BEST` | `/pools/{n}` -> `name`, `url`, `user`, `difficulty`, `best_share` |
| `pool` -> `JOB`, `H`, `N2SZ`, `N2` | `/pools/{n}` -> `job.id`, `job.height`, `job.extranonce2_size`, `job.extranonce2` |
| `pool` -> `ACC`, `REJ`, `STALE`, `SOLV` | `/pools/{n}` -> `shares.accepted`, `.rejected`, `.stale`, `.solved` |
| `pool` -> `PING`, `DISCO`, `WAIT`, `UPTIME`, `LAST` | `/pools/{n}` -> `ping_ms`, `disconnects`, `wait_time_s`, **`session_s`**, `last_share_age_s`. The binary key is `UPTIME` but the value is the **pool session**, which is why the REST name differs |
| `histo`, `scanlog`, `meminfo` | `/history`, `/scanlog`, `/meminfo` |
| `histo` -> `KHS` | `/history[]` -> `hashrate_hs`. **The binary key is mislabelled**: `histo`'s `KHS` already carries **H/s**, not kH/s, so this is the one mapping where the value does *not* change by 1000. Unchanged in the binary API for compatibility. |
| `switchpool\|n`, `seturl\|url`, `quit` | `POST /pools/switch`, `POST /pools/url`, `POST /quit` |

Every value that was a bare number in a `;`-separated record is now a typed JSON field, and
unavailable values are `null` instead of `0` or an empty string.

## 13. Changelog

| Revision | Change |
|---|---|
| 1.0 (unreleased) | Initial contract: read surface, write surface, control API, metrics. |
| 1.0 (unreleased) | Reconciled the two copies. New section 7.5 (a switch is refused with `409` when the target's workspace does not fit, `cpu` only). `features` is an array, not a delimited string. Section 10 corrected against both implementations: `/history`, `threads[].accepted`/`.rejected` and `summary.shares.stale` are served on `cpu`; `/scanlog` and `/meminfo` are permanently `501` there. Section 10's two `/control/profile` rows dropped: the Vulkan miner now applies an `algo` change, and a pool together with a run-state change, in one barrier pass costing one epoch, so neither row has a difference left to record. |
| 1.0 (unreleased) | Section 4: the token is matched exactly; the legacy WebSocket path is token-covered and a refused upgrade answers `401` rather than closing silently. Section 10: the write gate is split into remote and loopback rows, because the two miners differ on the local caller. |
| 1.0 (unreleased) | **Correction.** Sections 4 and 10 claimed a `gpu` miner grants loopback callers full access regardless of the write flag. That is true only of its legacy binary protocol; on this API every caller needs the write flag, measured. |
| 1.0 (unreleased) | Section 5 corrected: it claimed in one sentence that a routed `control.*` capability is listed and answers `403` without `--api-control`, and in the next that the capability list is derived from the `--api-control` gate. The first is what both miners do; the second is withdrawn. **A client must not infer that control is unavailable from `control.*` being listed, nor expect it to disappear when the gate is off.** |
| 1.0 (unreleased) | Section 6.8: `/config` is now stated to be the one response body whose **key set differs by miner kind**, because it mirrors each miner's own options. Found by running the first cross-miner conformance check with both miners live; every other endpoint's shape matched, or differed only where sections 9 and 10 already said it would. |
| 1.0 (unreleased) | **`uptime_s` split.** It meant *process uptime* at summary scope and *pool session length* at pool scope -- one name, two meanings, one nullability column, and the two contract files disagreed on whether the pool one could be `null`. The pool field is now **`session_s`** (nullable, resets on reconnect) and `uptime_s` means process uptime at every scope. **Both times are now queryable independently**, and a client reading `pools[].uptime_s` must move to `pools[].session_s`. |
| 1.0 (unreleased) | **A third implementation joins, and it shares a `kind` with an existing one.** Section 1 lists three miners; two report `gpu` and do not serve the same routes. **Section 10 no longer states route availability** -- that moves to the capability list of section 5, which is derived from the route table and cannot go stale -- and what remains there is field-level, per implementation. A client that inferred the existence of a path from `miner.kind` must read section 5 instead; nothing about an existing miner's behaviour changed. New: `devices[].vulkan` (section 6.3), three metric families (section 11), and section 7.5's memory pre-check restated per implementation because the two `gpu` miners differ on it. Section 7.1 now allows an implementation to retain an epoch-scoped dataset across a `pause`. |
| 1.0 (unreleased) | **Correction, section 11.** `miner_network_difficulty` and `miner_pool_difficulty` were published as `0` by every implementation when the miner had no value for them, contradicting this section's own *"absent rather than zero"* rule -- the shared renderer's input carried no way to say "unset" for these two. Both are now header-only until a value exists. A dashboard that read `0` as a real difficulty during a benchmark run, or in the seconds before a pool's first job, now sees no sample instead. |
| 1.0 (unreleased) | **The retained dataset becomes observable.** Section 7.1's allowance for holding an epoch-scoped dataset across a `pause` could only be inferred from the process's own footprint: `devices[].gpu.mem_bytes` is the card's total, a constant of the hardware, and was never able to carry it. Sections 6.3 and 8 gain **`devices[].vulkan.shared_table_bytes`** -- the table that device is holding right now, `null` when it holds none and never `0`, because a table of no size is not a state this reports. A manager weighing `pause` against `stop` can now read what a `pause` would keep rather than deduce it. Additive, and inside the Vulkan-only sub-object, so no other implementation owes code for it. |
| 1.0 (unreleased) | **The retry delay becomes a field.** Section 4 tells clients to branch on `code` and never on the prose in `message`, yet a `429`'s only statement of when to come back *was* that prose -- so the one thing a throttled manager needs was reachable only by the route this contract forbids. The error object gains **`retry_after_s`**, on `429` and no other status: whole seconds, rounded **up**, always `>= 1`, so a caller that waits it out is not refused a second time. `ready_for_switch` (section 7.2) answers *whether* before a call; this answers *when* after one, without a second round trip. Unlike the row above, this is not implementation-local -- every implementation that throttles owes the field. |
