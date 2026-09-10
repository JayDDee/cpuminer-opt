# cpuminer-opt — Project Documentation

A high-performance, multi-algorithm CPU miner for Linux, Windows, macOS and BSD,
optimized for x86-64 (SSE2 / AVX2 / AVX-512 / AES-NI / VAES) and aarch64
(NEON / ARMv8 crypto). It supports 100+ proof-of-work algorithms behind a single
binary, selected at runtime with `--algo`.

This folder holds developer-facing documentation: how the miner is structured, how
algorithms are implemented, and per-algorithm notes.

---

## What it does

cpuminer-opt connects to a mining pool (Stratum over TCP/SSL) or a node
(`getblocktemplate` over HTTP/HTTPS), repeatedly hashes candidate block headers
across all CPU threads, and submits any hash that meets the share target.

```
./cpuminer -a <algo> -o stratum+tcp://<pool>:<port> -u <wallet|user> -p <pass>
```

See `INSTALL_LINUX` / `INSTALL_WINDOWS` for build instructions and the top-level
`README.md` for the full list of supported algorithms and coins.

---

## How it is built (architecture)

### Runtime algorithm dispatch — the "gate"

Every algorithm plugs into a common dispatch table, `algo_gate_t`
(`algo-gate-api.h`). At startup the selected algorithm's `register_<algo>_algo()`
fills the gate with function pointers — most importantly `scanhash` (the nonce-scan
loop) and `hash` — plus optional hooks for work building, target handling, stratum
quirks, and CPU feature requirements. The main loop in `cpu-miner.c` then drives the
gate without knowing which algorithm is running.

Adding an algorithm means implementing its hash and a `register_` function, then
wiring one `case` into the registration switch — no changes to the mining core.

### Layered SIMD with a scalar fallback

Most hashes ship multiple implementations and the build/runtime picks the best the
CPU supports, in order:

```
AVX-512  →  AVX2  →  SSE4.2 / SSE2  →  NEON / ARMv8   →  scalar (portable C)
```

Where an algorithm allows it, the vector paths use **parallel-lane hashing**: 4, 8,
or 16 independent nonces are hashed at once, one per SIMD lane, which is the single
biggest throughput win on modern CPUs. AES-based rounds (Groestl, Echo, Shavite,
Fugue) use AES-NI / VAES hardware instructions where present.

### Source layout

| Path | Contents |
|---|---|
| `cpu-miner.c` | Thread management, the scan/submit loop, stratum and CLI. |
| `algo-gate-api.{c,h}` | The `algo_gate_t` dispatch table and per-algo registration. |
| `algo/<family>/` | One subdirectory per hash family (e.g. `blake/`, `x16/`, `gr/`, `flex/`). |
| `simd-utils/` | Width-portable SIMD intrinsic helpers shared by every algorithm. |
| `miner.h` | The algorithm enum, name table, and shared miner types. |

---

## Algorithm families (overview)

The supported algorithms group into a few broad families:

- **Single-hash coins** — `sha256d`, `blake`, `keccak`, `groestl`, `skein`,
  `whirlpool`, and their variants.
- **Chained "X" hashes** — `x11`/`x13`/`x16r`/`x17`/`x22i`/`x25x` and relatives,
  which run a fixed or header-selected sequence of core hashes.
- **Memory-hard** — `scrypt`, `yescrypt`/`yespower` family, `argon2d` family,
  `verthash`.
- **Equihash** — `equihash` 200/9 and the 96/125/144/192 variants.
- **CryptoNight-family chains** — GhostRider (`ghostrider`), Mike (`mike`) and Flex
  (`flex`): hybrids that interleave a set of fast core hashes with memory-hard
  CryptoNight rounds, with the order derived from the block header.

Per-algorithm documentation lives in [`algorithms/`](algorithms/):

- [GhostRider](algorithms/ghostrider.md) — Raptoreum (RTM)
- [Mike](algorithms/mike.md) — VKAX, FortuneBlock (FTB)
- [Flex](algorithms/flex.md) — Kylacoin / Lyncoin
- [x16r and the X16 family](algorithms/x16r.md) — Genix and variants
- [VerusHash 2.2](algorithms/verus.md) — Verus Coin (VRSC)
- [Odocrypt](algorithms/odocrypt.md) — DigiByte (DGB)
- [SHA256Dv](algorithms/sha256dv.md) — Veil (VEIL)
- [Equihash family](algorithms/equihash.md) — Zcash, Bitcoin Gold, Flux and others
- [yescrypt / yespower family](algorithms/yescrypt-yespower.md) — BitZeny, Koto, Yenten, MicroBitcoin and others
- [Argon2d family](algorithms/argon2d.md) — Credits, Dynamic, Unitus
- [Balloon](algorithms/balloon.md) — Mateable (MTBC)
- [Lyra2 family](algorithms/lyra2.md) — Vertcoin, Monacoin, Zcoin/Firo, Garlicoin
- [X-chains (x11–x17 and relatives)](algorithms/x-chains.md) — Dash and many others
- [SkyDoge](algorithms/skydoge.md) — SkyDoge
- [SHA3T](algorithms/sha3t.md) — BitcoinIII (BC3), Fjarcode (FJAR)
- [HeavyHash](algorithms/heavyhash.md) — Optical Bitcoin (OBTC), Ursula (URSA)
- [Simple & legacy hashes](algorithms/simple-hashes.md) — sha256d, blake, keccak, groestl, skein, quark and more

---

## Correctness

A mining algorithm is consensus-critical: a hash that is one bit different from the
network's definition is worthless. Every algorithm here is validated to produce
byte-for-byte identical output across all of its implementations (each SIMD path
must match the scalar reference), and several carry a built-in known-answer test
(KAT) that runs at startup and refuses to mine on mismatch. Final confirmation for a
new algorithm is always pool-accepted shares on a live network.
