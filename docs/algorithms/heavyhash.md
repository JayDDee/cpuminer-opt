# HeavyHash

**Coins:** Optical Bitcoin (OBTC), Ursula (URSA)
**Algorithm name:** `heavyhash`
**Family:** hash -> matrix multiply -> hash (the integer sibling of `hoohashv110`)

```
./cpuminer -a heavyhash -o stratum+tcp://<pool>:<port> -u <wallet> -p x
```

---

## Overview

HeavyHash sandwiches a 64×64 integer matrix-vector product between two SHA3-256 passes.
The matrix is not a constant: it is generated per block from a PRNG seeded by the previous
block hash, so every block mines against a different matrix.

```
seed        = SHA3-256( header[4..35] )              // the prev block hash
mat[64][64] = xoshiro256++( seed ) -> 4-bit values   // regenerated until full rank
first       = SHA3-256( header80 )
product[i]  = ( sum_j mat[i][j] * nibbles(first)[j] ) >> 10
digest      = SHA3-256( first ^ pack_nibbles(product) )
```

`nibbles()` splits each of the 32 bytes of `first` into its high then low nibble, giving 64
values in 0..15; `pack_nibbles()` is the inverse, and is well defined because each `product[i]`
fits a nibble (the largest possible sum is 64 × 15 × 15 = 14400, and 14400 >> 10 = 14).

The name is the design intent: oBTC's "optical proof of work" (oPoW) targets hardware where a
large matrix product is nearly free — an optical processing unit — so the matrix step is meant to
be the *cheap* part for the intended miner and the expensive part for everyone else.

oBTC is Bitcoin Core with the block hash swapped for the PoW hash, exactly like BC3/`sha3t`:
`CBlockHeader::GetHash()` simply calls `GetPoWHash()`. So a published oBTC block hash is a
ready-made test vector — see *Verification*.

### Two coins, one implementation

URSA's heavyhash is byte-identical to OBTC's — `src/crypto/heavyhash.cpp`,
`src/crypto/xoshiro256pp.h` and the matrix generator all match, and the seed is the same
`SHA3-256(hashPrevBlock)`. The one difference is history, not consensus: **Ursula began as an X11
chain and forked to heavyhash at `nHeavyHashActivationTime`**, so its blocks before that timestamp
hash with X11 and are useless as heavyhash test vectors. Current mining on both chains uses the
same code path.

## Padding: SHA3, not Keccak

Both hash passes are **NIST FIPS 202 SHA3-256** (domain separation byte `0x06`), not
pre-standard Keccak-256 (`0x01`). In this tree the selector is the global `hard_coded_eb`, which
`register_heavyhash_algo` sets to `6` before the self-test runs. The daemon uses `tiny_sha3`,
which confirms the same choice on its side.

## Digest byte order

The 32 output bytes are consumed directly as little-endian `uint32` words, which is what
`valid_hash` expects, so **there is no byte reversal before the target comparison**. This is worth
stating because the closely related `hoohashv110` needs one — its digest is big-endian. An
explorer displays an oBTC block hash in the reverse of the internal order, as with Bitcoin.

Because `valid_hash` already short-circuits on word 7, no separate high-word prefilter is
worth writing here (`hoohash` needs one only because it must byte-reverse first).

## Implementation

`algo/heavyhash/heavyhash.c`, one scalar path. The structural work is in the split:

| Half | Cost driver | Where |
|---|---|---|
| `heavyhash_matrix_gen` | 256 PRNG draws + a 64×64 rank check | **once per `scanhash` call** |
| `heavyhash_core` | 2 × SHA3-256 + 4096 multiply-accumulates | once per nonce |

The matrix seed reads header bytes 4..35 only — never the nonce at bytes 76..79 — so the matrix
is constant across a whole nonce range and is hoisted out of the loop. This is the same lever as
hoohash's per-job matrix hoist, and a larger share of the work here because generation also pays
for the rank check.

### The full-rank gate

The daemon regenerates the matrix while `!Is4BitPrecision(matrix) || !IsFullRank(matrix)`. This
implementation does neither of those literally, deliberately:

- `Is4BitPrecision` asks whether every entry is <= `0xF`. Entries are produced by
  `(value >> (4*shift)) & 0xF`, so this is true by construction and the check can never fire.
- `IsFullRank` runs a 64×64 **SVD** and rejects when the smallest singular value is below
  `1.000009e-12`. A widely-copied miner-side reference instead runs double-precision
  Gauss-Jordan with a `1e-9` threshold. That those two disagree in the near-singular regime,
  and that nobody has noticed, is the tell: **the branch is unreachable in practice**. A 64×64
  matrix with entries drawn uniformly from {0..15} is singular with probability far below
  2^-100, so the loop runs exactly once on any real chain and all variants agree.

So rank is computed **exactly over a prime field** instead. Full rank mod *p* implies
nonsingular over the rationals, which implies the SVD accepts; a nonsingular matrix can lose rank
modulo one prime with chance ~1/*p*, so a second prime is consulted before declaring singular,
which puts a spurious regeneration below 1e-18 per job.

The payoff is determinism. There is **no floating point anywhere in this algorithm** as
implemented, so unlike hoohash — where the FP *is* the consensus and had to be pinned against
FMA contraction and libm versions — nothing here can be perturbed by `-Ofast`, by x87 excess
precision, or by a compiler upgrade. The `-Ofast` aarch64 build is verified to produce identical
digests (see below).

## Verification

A known-answer test runs at startup and **refuses to mine on mismatch**. Six vectors in two
groups, chosen so that neither group can cover for a defect in the other:

**Whole-hash vectors** over an 80-byte header — these drive the seed derivation, matrix
generation, both SHA3 passes, the nibble packing and the byte order together.

| # | Vector | Anchored by |
|---|---|---|
| 0 | oBTC **mainnet genesis** header | `chainparams.cpp` asserts `hashGenesisBlock == 0000000000115c7a...`; also verified to meet its own `nBits` |
| 1 | oBTC **testnet genesis** header | same, `== 00000000248ecbf0...` |
| 2 | header with a **non-zero prevhash** | independent reimplementation (below) |

Vector 2 exists because *both* genesis blocks have a zero prevhash, so without it nothing in the
file would notice if the matrix seed read the wrong 32 header bytes.

**Core vectors** — the daemon's own functional-test vectors
(`test/functional/heavy_hash.py`), run verbatim against its hardcoded reference matrix. These pin
the matrix multiply, the `>> 10` reduction, the nibble order and the xor *independently of matrix
generation*, so a compensating pair of errors in generation and core cannot hide. The Python test
matrix was confirmed byte-identical to the C++ `reference_matrix` in
`src/crypto/heavyhash_dummyArray.h` before use.

Beyond the startup KAT:

- **Independent reimplementation.** A transcription of the daemon (`hash.cpp`,
  `xoshiro256pp.h`, `crypto/heavyhash.cpp`, `primitives/block.cpp`) in Python using `hashlib`'s
  SHA3-256 — a different implementation of the primitive than this tree's `sph_keccak` —
  reproduces all three daemon core vectors, both genesis hashes, and **48/48 digests over 12
  distinct matrix seeds** from the C build.
- **Build matrix, bit-exact.** Seven builds emit an identical 48-digest stream
  (`md5 e54052589556bfff034e9cd004171fde`): x86-64 AVX-512 native, x86-64 with no SIMD at all
  (`-march=x86-64`), aarch64 under qemu, and **four native builds on real aarch64 hardware**
  (RK3588S: `-O2`, `-O3`, `-Ofast`, and a plain `-O3` with no `+crypto` in the march string).
  The startup self-test passes in all of them, including `-Ofast` — worth checking explicitly,
  since that is what this tree uses on ARM and what breaks hoohash. GCC 11 and clang 14 both
  compile the translation unit warning-free at `-Wall -Wextra`.

### Pool-confirmed on both architectures

zpool `heavyhash` (port 5138), 2026-08-22, stratum difficulty 0.05 against network 1.26k. This is
the part a KAT cannot prove — the merkle root and the difficulty scale are built by the Stratum
layer, not by the hash function.

| Build | Result |
|---|---|
| x86-64 (i7-11700F, AVX-512, `-t 16`) | **4 / 4 accepted**, 0 rejected, 2 sessions |
| aarch64 (RK3588S, `-O2 +crypto`, `-t 8`) | **5 / 5 accepted**, 0 rejected, **4 blocks** (279447-279450), 30 min |

**9 / 9 accepted, 0 rejected across two independently built binaries on two architectures.**

The aarch64 run matters for a reason specific to this algorithm: it spanned **four blocks**, so the
matrix was regenerated from three fresh prevhash seeds mid-session and every share still validated.
An offline KAT cannot reach that path — it only ever sees the seeds baked into its vectors.

- **`opt_target_factor = 1.0` is confirmed.** Accepted share difficulties ran from 0.0507 to 2.848
  against a 0.05 target — all above it, with no systematic offset, and the closest only 1.01× the
  target. A 256× error in either direction would instead have produced "low difficulty" rejects.
  Note that **every session ran at the same stratum difficulty (0.05)**, the only value the pool
  issued, so the runs are independent in architecture but not in difficulty; sampling a
  far-apart difficulty would be a stronger check, since a constant scaling error cannot hide
  across one.
- **The merkle hash function is confirmed, the branch folding is not.** Every job in every session
  had `Tx 0` and an empty merkle-branch list, so the root was just `sha256d(coinbase)`. That rules
  out a `sha3d`-style merkle root (see [SHA3T](sha3t.md)), but a multi-transaction job has still
  not exercised branch folding. OBTC blocks are near-empty in practice, so this is hard to arrange
  deliberately.

## Performance

**No trustworthy baseline exists yet.** The figures taken during the port came off a machine that
was running other work at the same time, so they are withdrawn rather than recorded — including the
`TTF @ ... kh/s` lines from the pool sessions, which moved by 1.4× between two consecutive jobs.
Note also that in pool mode cpuminer reports `TTF @ X h/s` and not `Total:`.

Sizing this properly needs an idle machine, at least 60 s of samples, and separate x86-64 and
aarch64 numbers. Until then, treat any hashrate quoted for heavyhash as unmeasured.

## Possible optimizations (preview)

Nothing beyond the per-job matrix hoist has been done, and no profile has been taken. Candidates,
in the order the structure suggests:

- **SIMD across nonces.** The matrix product is 4096 integer multiply-accumulates over values
  that fit in 4 bits, against a job-constant matrix — a good fit for wide integer lanes, and
  unlike hoohash there is no FP determinism risk in vectorising it. Lane width has to be measured
  from scratch here: hoohash rejected AVX-512 8-wide and NEON 4-wide, but for a reason that does
  not carry over (most of its runtime is scalar `libm`, and heavyhash calls none).
- **Working-set pressure.** A `uint32` 64×64 matrix is 16 KB, which is already L1-sized on many
  parts; a narrower element type (the values need 4 bits) would cut that fourfold and may matter
  more than lane width once several lanes multiply it.
- **Where the time actually goes** is unmeasured: two SHA3-256 passes over 80 and 32 bytes
  against 4096 MACs. The tree's shared n-way Keccak cores (used by `sha3t`, and already driven
  from pre-padded state there) are available for the hash halves if they turn out to dominate.
