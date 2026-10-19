# Lyra2 family

**Coins:** Vertcoin (historic), Monacoin, Zcoin/Firo, Garlicoin and others
**Algorithm names:** `lyra2re`, `lyra2rev2`, `lyra2rev3`, `lyra2z`, `lyra2z330`,
`lyra2h`, `allium`
**Family:** chained hashes built around the Lyra2 memory-hard KDF

```
./cpuminer -a lyra2rev3 -o stratum+tcp://<pool>:<port> -u <wallet> -p x
```

---

## Overview

Lyra2 is a memory-hard key-derivation function built on a cryptographic sponge. Each
algorithm in this family wraps one or more **Lyra2** invocations in a short chain of
ordinary 256-bit hashes (blake256, keccak256, cubehash256, skein256, groestl256,
bmw256). The surrounding hashes provide diffusion; the Lyra2 step(s) provide the
memory hardness that keeps these algorithms relatively CPU-friendly.

All of them take the standard 80-byte header and produce a 32-byte hash using the
standard Bitcoin-style Stratum flow (32-bit nonce at header word 19) — there is no
protocol customization.

### Lyra2 cost parameters

Each Lyra2 call is parameterized `(timeCost T, rows R, cols C)`. Memory use grows
with `R × C`; compute grows with `T` and `R`. The family spans a wide range, from
cheap (`1, 8, 8`) to deliberately heavy (`2, 330, 256` ≈ 8 MiB per hash).

### blake256 midstate caching

Most variants start with blake256 over the header. Because only the last 16 bytes of
the header (containing the nonce) change between attempts, the blake256 state after
the first 64-byte block is computed once per work item and reused across the nonce
scan.

## Variants

| Algo | Chain | Lyra2 `(T,R,C)` | Notes / coins |
|---|---|---|---|
| `lyra2re`   | blake → keccak → **Lyra2** → skein → groestl | 1, 8, 8 | "Lyra2RE" — Vertcoin (original) |
| `lyra2rev2` | blake → keccak → cubehash → **Lyra2** → skein → cubehash → bmw | 1, 4, 4 | "Lyra2REv2" — Vertcoin v2, Monacoin |
| `lyra2rev3` | blake → **Lyra2** → cubehash → **Lyra2** → bmw | 1, 4, 4 (×2) | "Lyra2REv3" — Vertcoin v3 |
| `lyra2z`    | blake → **Lyra2** | 8, 8, 8 | Zcoin (XZC) / Firo |
| `lyra2z330` | **Lyra2** directly over the 80-byte header | 2, 330, 256 | high-memory variant (~8 MiB/hash) |
| `lyra2h`    | blake → **Lyra2** | 16, 16, 16 | high time-cost variant |
| `allium`    | blake → keccak → cubehash → **Lyra2** → cubehash → **Lyra2** → skein → groestl | 1, 8, 8 (×2) | Garlicoin (GRLC), Tuxcoin |

(`phi2` also uses a Lyra2 step inside a larger chain, but is documented with the X/phi
algorithms rather than here.)

## Performance

- **Parallel-lane hashing.** Several variants ship 4-way (AVX2), 8-way, and 16-way
  (AVX-512) implementations, hashing many nonces at once, plus a 2-way Lyra2 sponge.
- **Hardware AES.** Variants ending in groestl (`lyra2re`, `allium`) use the AES-NI
  groestl256 core.
- **Per-thread Lyra2 matrix.** The high-memory variants (`lyra2z330`) allocate their
  Lyra2 matrix once per thread and reuse it across the whole nonce scan.

## Verification

Each implementation (every SIMD width and the scalar reference) produces byte-for-byte
identical output; correctness is confirmed by pool-accepted shares.

## Possible optimizations (preview)

- **Wider Lyra2 sponge** — extend the 2-way sponge to AVX-512 lanes so the
  memory-hard step keeps pace with the wide core-hash paths.
- **Matrix reuse across jobs** — keep the per-thread Lyra2 matrix allocated across
  work items (not just within one scan) to avoid reallocation overhead, especially for
  `lyra2z330`.
- **NUMA-aware matrices** — for the high-memory variants, place each thread's matrix on
  its local NUMA node on multi-socket machines.
