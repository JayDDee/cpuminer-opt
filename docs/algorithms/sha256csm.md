# SHA256csm (Galleoncoin)

**Coin:** Galleoncoin (GALE)
**Algorithm name:** `sha256csm` (aliases: `gale`, `galleon`)
**Family:** double SHA-256, over an extended pre-image

```
./cpuminer -a sha256csm -o stratum+tcp://<pool>:<port> -u <wallet> -p x
```

---

## Overview

SHA256csm is double SHA-256 with one change: the first hash covers the 80-byte block
header **zero-extended to 112 bytes**.

```
hash = SHA256( SHA256( header80 || 32 zero bytes ) )
```

That is the entire algorithm. Standard initialization vector, no truncation, full
256-bit digest, 32-bit nonce, ordinary Bitcoin-style Stratum flow and difficulty scale
— the share target needs no scaling factor.

Galleoncoin is a PIVX-derived masternode chain that uses SHA256csm for proof of work.

## Hash structure

112 bytes still spans two 64-byte SHA-256 blocks, exactly as 80 bytes does, so the cost
per nonce is **identical to `sha256d`**: the first block is nonce-independent and is
prehashed once per job as a midstate, leaving two compressions per nonce.

The extension changes only where the padding lands in the second block:

| Word | `sha256d` | `sha256dt` | `sha256csm` |
|---|---|---|---|
| 0-2 | header words 16-18 | header words 16-18 | header words 16-18 |
| 3 | nonce | nonce | nonce |
| 4 | `0x80000000` | `0x80000000` | 0 |
| 5-11 | 0 | 0 | 0 |
| **12** | 0 | 0 | **`0x80000000`** |
| 13-14 | 0 | 0 | 0 |
| **15** | `0x280` (640 bits) | `0x480` | **`0x380`** (896 bits) |

The nonce stays at `W[3]`, and the second SHA-256 (over the 32-byte intermediate digest)
is unchanged from `sha256d`.

## WARNING: the family's prehash fast path does not apply here

`sha256d`, `sha256t` and `sha256dt` share an optimized schedule in
`sha256-hash.c` / `sha256-hash-4way.c`: `prehash_3rounds` computes the first three rounds
of the second block once per job, and `final_rounds` completes it per nonce. Those
helpers are **specialized on `W[12] == 0`**, which is true for every other member of the
family and is exactly what SHA256csm changes.

With `W[12] = 0x80000000` they omit message-schedule terms that are no longer zero, so
reusing them here produces **wrong digests with no compile error and no warning**. The
startup self-test catches it; a casual "optimize it like `sha256d`" edit would not be
caught by anything else until the pool rejected every share.

SHA256csm therefore has its **own** schedule code, `sha256csm_{16x32,8x32,4x32}_prehash_3rounds`
and `_final_rounds`, which carry the `W[12]` terms the stock helpers drop. They live beside
their siblings in `sha256-hash-4way.c` because the round macros are file-local, and they are
purely additive — no shared function was modified.

The definitive-loser short transform (`transform_le_short`) **is** reusable and is used: the
second block's shape is identical to `sha256d`'s.

## Implementation

All widths live in `algo/sha/sha256csm.c`; the paths are compile-exclusive.

| Path | Width | Selected when |
|---|---|---|
| `scanhash_sha256csm_16x32` | 16 nonces | AVX-512 |
| `scanhash_sha256csm_x86_x2sha` | 2 nonces | x86-64 with SHA-NI |
| `scanhash_sha256csm_neon_x2sha` | 2 nonces | aarch64 with the ARMv8 SHA2 extension |
| `scanhash_sha256csm_8x32` | 8 nonces | AVX2 |
| `scanhash_sha256csm_4x32` | 4 nonces | SSE2 or NEON |
| `scanhash_sha256csm_ref` | 1 nonce | everything else |

Which path a binary actually compiled is printed in its startup self-test line, for
example `sha256csm self-test PASSED [16x32 AVX-512]`. That line is the only reliable
indicator — the `CPU features:` banner reports what the *processor* supports, which is
not the same thing as what the binary was built for.

## Verification

A known-answer test runs at startup and **refuses to mine on mismatch**. It layers three
checks, because each one is blind to a different class of mistake:

1. **Reference KAT** — anchors the 112-byte pre-image. A build that quietly hashed 80
   bytes fails here.
2. **Block-layout differential** — 16 nonces through the scanhash block construction,
   compared against the byte-oriented reference. This is what pins the padding word and
   bit count; the KAT never touches that code.
3. **Per-width lane differential** — the compiled vector path's own block setup, diffed
   lane by lane against the anchored scalar. Each path declares the padding independently,
   so a typo in one width's `buf[12]` would otherwise surface only as pool rejects.

Unlike some other coins in this tree, **a published GALE block hash is not a usable test
vector.** Galleoncoin is PIVX-derived, so a block id is `sha256d` of the header and is
not the proof-of-work hash. The vectors are therefore derived from the algorithm
definition and labelled as such, rather than taken from chain data.

End-to-end correctness is confirmed by pool-accepted shares on every path:

| Path | Toolchain | Result |
|---|---|---|
| x86-64, AVX-512 16x32 | gcc | 7 accepted, 0 rejected |
| x86-64, SHA-NI 2-way | gcc | 21 accepted, 0 rejected |
| x86-64, AVX2 8x32 | gcc | 20 accepted, 0 rejected |
| x86-64, SSE2 4x32 | gcc | 12 accepted, 0 rejected |
| x86-64, scalar | gcc | 6 accepted, 0 rejected |
| aarch64, 2-way NEON SHA2 | gcc | 3 accepted, 0 rejected |
| aarch64, 2-way NEON SHA2 | **clang, Android/bionic** | 6 accepted, 0 rejected |
| aarch64, NEON 4x32 | gcc | 10 accepted, 0 rejected |

**85 accepted, 0 rejected — every path, no exceptions.** Because the paths are
compile-exclusive, each was built as its own binary and mined separately; a confirmation on one
path says nothing about the others. Runs spanned stratum difficulties 0.1 to 1.0, which is what
establishes that the share target needs no scaling factor.

The Android row is a separate toolchain rather than a duplicate of the row above it: everything
else here is gcc against glibc, so the Termux build is the only clang compile and the only
non-glibc target the algorithm has been through.

Testing the scalar path needs `-DSHA256CSM_FORCE_SCALAR`. On x86-64 `__SSE2__` is baseline, so
the scalar `#else` branch is unreachable in a normal build; the override compiles exactly the
branch a target without SSE2 or NEON would select.

## Performance

Throughput tracks `sha256d`, as the identical compression count predicts. SHA256csm used to
sit ~5% below it, because it could not reuse the family's per-job prehash; with its own
schedule code that gap is closed, at 1 thread on an i7-11700F, AVX-512:

| Algorithm | H/s (1 thread) |
|---|---|
| `sha256csm` | 37.83 MH/s |
| `sha256d` | 37.72 MH/s |
| `sha256dt` | 37.79 MH/s |

Per-path figures, all threads. The three machines differ in microarchitecture, clock and
compiler, so compare only within a machine:

| Machine | Path | 1 thread | All threads |
|---|---|---|---|
| i7-11700F 8C/16T | 16x32 AVX-512 | 37.83 MH/s | ~165 MH/s |
| | 2-way SHA-NI | 13.90 MH/s | ~126 MH/s |
| i7-7700K 4C/8T | 8x32 AVX2 | 13.32 MH/s | 51.9 MH/s |
| | 4x32 SSE2 | 5.535 MH/s | 21.9 MH/s |
| | scalar | 2.421 MH/s | 9.356 MH/s |
| RK3588S 4xA76+4xA55 | 2-way NEON SHA2 | 6.899 MH/s | 87.9 MH/s |
| | 4x32 NEON | 1.357 MH/s | 18.2 MH/s |

Two things worth noting. **AVX-512 is 2.7x faster than SHA-NI on the same CPU**, so the 16-wide
path is the right default even though SHA-NI is dedicated hardware; on ARM the ordering is the
reverse, with NEON SHA2 5.1x the NEON 4x32 fallback. And **SMT contributes almost nothing here**
— all-thread throughput is ~3.9x on 4 physical cores — which is expected for a pure ALU kernel
with no memory stalls to hide.

### aarch64: build with the crypto extension

On a Rockchip RK3588S (Cortex-A76 + A55, 8 threads) the ARMv8 SHA2 extension is worth
**5.6x** — 87.9 MH/s with it against 15.6 MH/s without. That is far larger than its
effect on most algorithms in this tree, because SHA-256 has dedicated ARM instructions
while, for example, the Minotaur family does not.

This needs no configuration for a native build: `-march=native` on that SoC resolves to
`armv8.2-a+crypto+...` and selects the 2-way NEON SHA2 path automatically. It matters
only if you are producing a **portable** ARM binary — a generic `-march=armv8-a` build
silently drops to the 4x32 NEON path and loses that factor. Check the self-test line.

## Possible optimizations (preview)

- ~~A csm-specific 3-round prehash.~~ **Done** — worth **+5.3%** on both the AVX-512 and AVX2
  paths and **+6.6%** on NEON 4x32. `W[3]` is still the nonce, so 3 rounds remains the
  theoretical ceiling and the SIMD paths now reach it. Not applicable to the SHA-NI or NEON
  SHA2 paths, where intermediate round state is inaccessible between hardware rounds.
- ~~The 4x32 path lacked the definitive-loser abort.~~ **Done** — `sha256_4x32_transform_le_short`
  was declared but never implemented; writing it is worth a further **+4.7%** on that path
  (**+11.7%** cumulative). It is generic SHA-256, so `sha256d`/`t`/`dt` could take the same
  abort at 4x32; they are not wired to it.
- **Wider SHA-NI batching.** The x86 SHA-NI and NEON SHA2 paths process 2 nonces; the
  interleaving depth was inherited from `sha256dt` rather than tuned for this algorithm.
