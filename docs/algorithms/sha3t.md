# SHA3T (SHA3-256t)

**Coins:** BitcoinIII (BC3), Fjarcode (FJAR)
**Algorithm name:** `sha3t` (alias: `sha3-256t`, the pool-side name)
**Family:** iterated single-primitive hash

```
./cpuminer -a sha3t -o stratum+tcp://<pool>:<port> -u <wallet> -p x
```

---

## Overview

SHA3-256t is NIST SHA3-256 applied three times to the 80-byte block header:

```
hash = SHA3-256( SHA3-256( SHA3-256( header80 ) ) )
```

That is the entire algorithm. It uses the standard Bitcoin-style Stratum flow (80-byte
header, 32-bit nonce) and an unmodified Bitcoin difficulty scale, so the share target
needs no scaling factor.

BitcoinIII is Bitcoin Core with exactly one consensus change: the block hash *and* the
proof-of-work hash are SHA3-256t instead of SHA-256d. Because the block hash is the PoW
hash, a published BC3 block hash is a ready-made test vector — see *Verification*.

The design goal is ASIC/rental resistance by novelty rather than by cost: there is no
SHA3-256t rental-hashrate market, so an attacker cannot rent compatible hashpower.

## Padding: SHA3, not Keccak

The primitive is **NIST FIPS 202 SHA3-256** (domain separation byte `0x06`), not the
pre-standard Keccak-256 (`0x01`) that Ethereum and `-a keccak` use. Getting this wrong
changes every digest. In this tree the selector is the global `hard_coded_eb`, which
`register_sha3t_algo` sets to `6`.

## WARNING: Merkle root: sha3t is *not* sha3d

`sha3d` overrides the Stratum merkle-root construction to hash the coinbase with `sha3d`.
**`sha3t` does not** — it uses the ordinary `sha256d` merkle root, like Bitcoin. The two
algorithms are one character apart in the name and take opposite answers here.

Getting this wrong is silent: the startup KAT still passes (the hash function is right),
the miner reports a healthy hashrate, and the pool rejects every share as invalid. If you
see "Invalid share" with a passing KAT, look at the merkle root before the hash.

This is settled from chain data, not from the coin's name. Recomputing the merkle root of
BC3 blocks 44172 (4 tx), 39663 (2 tx) and 53000 (2 tx) from their transaction ids
reproduces each header's `merkleroot` field exactly with `sha256d`, and produces an
unrelated value with `sha3d`.

## Implementation

| Path | Width | Selected when |
|---|---|---|
| `scanhash_sha3t_8way` | 8 nonces | AVX-512 — drives the permutation from pre-padded state |
| `scanhash_sha3t_4way` | 4 nonces | AVX2 |
| `scanhash_sha3t_2x64` | 2 nonces | SSE2, **or** NEON *with* the ARMv8.2 SHA3 extension |
| `scanhash_sha3t` | 1 nonce | everything else — including **aarch64 without that extension** |

WARNING: Note the last two rows: unlike `sha3d` and `keccak`, which take the 2×64 path on any NEON
target, `sha3t` only does so when `__ARM_FEATURE_SHA3` is defined. On ARM parts lacking it the
scalar path is faster — see *Performance* below. Which path a binary chose is visible in its
startup self-test line (`sha3t 2-way self-test PASSED …` versus `sha3t self-test PASSED …`).

The batched paths reuse the shared n-way Keccak cores in `algo/keccak/`, so `sha3t`
shipped batched from the start rather than scalar-first. Note that the scalar and batched
loops use different nonce conventions, inherited from `sha3d`/`keccak` — see the comment
at the top of `sha3t-4way.c` before writing any 1-way vs n-way comparison.

## Verification

A known-answer test runs at startup and **refuses to mine on mismatch**. Because a BC3
block hash *is* the sha3t digest of its header, the vectors are two real mainnet block
headers — **44172** and **39663** — rather than synthetic inputs, so they pin the
algorithm to the live chain's consensus, not just to another implementation.

Both are post-fork blocks: BC3 selects the block-hash algorithm on version bit 12 and
only sets it from height 30240 on, so a pre-fork block hashes with SHA-256d and is
useless as an anchor.

On builds with a batched path, the KAT anchors the scalar reference and the batched path
is then compared against it lane-by-lane over 64 randomised headers, so every lane and
the interleave/extract plumbing are covered too.

End-to-end correctness is confirmed by pool-accepted shares. That is the part a KAT cannot
prove — the merkle root is built by the Stratum layer, not by the hash function, so only a live
pool can rule out the trap described above.

**Both submit conventions are confirmed separately**, because the scalar and batched loops do not
submit alike (see *Implementation*):

| Path | Result |
|---|---|
| batched (x86, AVX-512 8-way) | **18 / 18 accepted**, 0 rejected, 2 block changes |
| scalar (aarch64) | **75 / 75 accepted**, 0 rejected, ~19 block changes |

Observed share difficulties cluster just above the stratum target with no systematic offset, which
is what confirms the difficulty scale needs no correction factor.

## Performance

Keccak-f keeps **25 lanes live**, and on x86 that single fact decides how each build performs.
AVX-512 has 32 vector registers and fits the state; AVX2 and SSE2 have 16 and spill. Measured
per-lane throughput against the scalar reference is **109% (AVX-512), 74% (AVX2), 66% (SSE2)** —
the AVX-512 path is *superlinear* only because the scalar path is itself spilling out of 16
general-purpose registers.

### WARNING: aarch64: the scalar path is currently the faster one

That register argument does **not** carry over to ARM, and measurement on a Rockchip RK3588S
(Cortex-A76 + A55) shows the opposite of what it predicts: the NEON 2×64 path reaches only
**49% per-lane efficiency**, and the plain scalar build beats it — by **3% on an A76 core, 35%
on an in-order A55 core, and 12% across all eight**.

The cause is not registers but a missing instruction. NEON has no 64-bit rotate, so each of
Keccak's rotations becomes a shift plus `SLI`, which is destructive, two-cycle, and issues on a
single pipe; an out-of-order A76 hides most of that stall and an in-order A55 cannot. Scalar
aarch64 has a one-cycle `ROR` on several pipes and can fold it directly into the XOR
(`EOR Xd,Xn,Xm,ROR #n`).

ARMv8.2's optional SHA3 extension (`EOR3`, `BCAX`) changes this, and `simd-utils` already uses it
when `__ARM_FEATURE_SHA3` is defined — but neither the A76 nor the A55 implements it. **The build
therefore selects the scalar path automatically on ARM targets without that extension**, which is
worth 35% on the little cores and 11% device-wide on an RK3588S. Nothing needs to be configured;
if you are building for an ARM part that *does* have it (Neoverse V1/N2, Cortex-A710/X2 and later,
Apple silicon), add `+sha3` to the march string and the 2×64 path comes back.

## Possible optimizations (preview)

The hash is three Keccak-f[1600] permutations and nothing else, each already running at the
widest lane a 64-bit state allows, in a kernel that already uses ternary logic and native
rotates. The open candidates:

- ~~Select the scalar path on ARM parts without the SHA3 extension.~~ **Done** — see above.
- ~~Match upstream on the 8-way AVX-512 kernel.~~ **Done.** The shared Keccak round had two
  avoidable costs: theta recomputed each column parity twice, and the 24-round loop was not being
  unrolled. Fixing both is worth **~7.7% on AVX-512 and ~5.8% on AVX2/SSE2**, and closes most of
  the distance to the Keccak team's own XKCP implementation. Note the unroll helps *only* the
  8-way path — on AVX2 and SSE2 it measured a 5–6% loss, because those have half the vector
  registers and a 25-lane Keccak state already spills.
- ~~Bypass the keccak context API.~~ **Done on the AVX-512 path**, worth ~1.11×. All three
  messages are a single SHA3-256 rate block whose padding is known at compile time, so the
  8-way path now drives the permutation from pre-padded state — no context, buffer copy or
  finalize step. A neat consequence: because the implementation keeps Keccak's lane-complement
  representation between passes, the digest lanes carry from one pass to the next untouched,
  removing 16 of the 18 complement operations a three-pass chain would otherwise pay. The 4-way
  and 2-way paths still use the context API and could get the same treatment.
- **First-permutation precompute is *not* a lever on CPU** (≈0.1% of a hash): the nonce reaches
  every row before round 1 finishes, so almost nothing is precomputable. It pays on GPUs for a
  different reason — constant-memory layout, not arithmetic.
