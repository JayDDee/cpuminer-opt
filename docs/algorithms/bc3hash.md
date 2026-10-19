# bc3hash

**Coin:** Bitcoin III (BC3)
**Algorithm name:** `bc3hash` (alias `bc3`; `-a bc3hash:W` sets the curve table window)
**Family:** elliptic-curve PoW — the second public-key PoW in this miner, after [curvehash](curvehash.md)

```
./cpuminer -a bc3hash -o stratum+tcp://<pool>:<port> -u <wallet> -p x
```

---

## Read this first: expected speed

**~530 H/s per thread**, so roughly **4.2 kH/s on an 8-thread desktop**. A single modern
GPU is orders of magnitude ahead of that.

This is not a bug and not a misconfiguration. BC3Mix spends its time in fixed-base
secp256k1 scalar multiplications and 256-bit modular exponentiations, and there is no
SIMD trick that closes the gap. Like curvehash, this algorithm is supported for
coverage and correctness parity, not because CPU mining it is competitive.

Startup builds 256 MB of curve tables at the default window before the first nonce:
about 1.3 s on an i7-7700K and 7 s on an RK3588S. See the
[Window and startup cost](#window-and-startup-cost) section below.

Measured baselines (2026-10-16, both pool-confirmed, Intel Xeon E5-2680 v4 @ 2.40 GHz):

| Machine | Threads | Window | Total | Per thread |
|---|---|---|---|---|
| Xeon E5-2680 v4 (28 cores) | 1 | 16 | 530 H/s | 530 H/s |
| Xeon E5-2680 v4 | 8 | 16 | 4.24 kH/s | 530 H/s |
| Xeon E5-2680 v4 | 8 | 10 | 3.55 kH/s | 444 H/s |

The window matters more to throughput than to memory: at 8 threads the larger table
raises per-thread rate by ~19%, because 8 threads' working sets fight over cache at
window 10 while the coarser digit table at 16 does not.

## Overview

Bitcoin III is a 1:1 Bitcoin fork. Header handling is stock: 80 bytes, nonce at word
19, sha256d merkle root, generic Bitcoin Stratum, plain 256-bit target read as a
little-endian `uint32[8]`, `opt_target_factor` 1.0. **The only difference is the PoW
function**, which replaces sha256d.

## Structure

Six standard hashers run over the same 80-byte header, each prefixed with a domain
tag, and their outputs are recombined by a custom mixing function:

```
domain = "BC3Hash-BlockHash-Algorithm/BitcoinIII-PoW/2026"

sha3_512 = SHA3-512( domain ‖ "/SHA3-512" ‖ header )
sha3_384 = SHA3-384( domain ‖ "/SHA3-384" ‖ header )
sha512   = SHA-512 ( domain ‖ "/SHA-512"  ‖ header )
ripemd   = RIPEMD-160( domain ‖ "/RIPEMD-160" ‖ header )
b2s      = BLAKE2s-256( domain ‖ "/BLAKE2s" ‖ header, PERSONAL = person_s )
b2b      = BLAKE2b-512( domain ‖ "/BLAKE2b" ‖ header, PERSONAL = person_b )

mix      = BC3Mix( sha3_512 )                       32 bytes

powhash  = SHA3-256( domain ‖ "/SHA3-256"
                     ‖ sha3_384 ‖ mix ‖ sha512 ‖ ripemd ‖ b2s ‖ b2b )
```

BLAKE2 uses the **PERSONAL** field, never KEY and never SALT.

### BC3Mix

The part with no analogue anywhere else in this miner. 64 rounds of arithmetic in
three widths, then a 64-step finalisation. State words add with plain wraparound;
the moduli below belong to the multiplications and powerings inside each round:

```
64-bit   32 rounds   powers and products mod 2^64  − 59, table power mod 2^64  − 1469
128-bit  16 rounds   powers mod 2^128 − 159,              table power mod 2^128 − 15449
256-bit  16 rounds   powers and products mod 2^256 − 189,
                     plus 4 secp256k1 scalar multiplications per round
final    64 steps    table power and one field inversion mod 2^256 − 36113 per step
```

The 64-bit and 128-bit message schedules are expanded from the 64-byte SHA3-512 output.

Every 256-bit round performs **four fixed-base secp256k1 scalar multiplications** —
four tables keyed on four arbitrary base points H, J, K, L, not on the generator G —
and four fixed-exponent modular powerings, so 64 scalar multiplications per hash. The
scalar multiplications dominate.

The moduli are all `2^n − C` with small C, so reduction is two carry folds rather
than a division. Each finalisation inversion is a binary extended-Euclid that infers
several exact quotients at once from intervals around the top 62 bits.

All rounds are **strictly serial within a nonce** — round *r+1*'s scalars are derived
from round *r*'s state. Each thread therefore runs 16 nonces in lockstep. Their
arithmetic stays separate, but every field inversion (the four curve multiplications
of each 256-bit round and the 64 finalisation steps) is shared across the lanes with
Montgomery's trick: one inversion plus a few multiplications instead of sixteen.

On CPUs with AVX-512 IFMA (Ice/Tiger/Rocket Lake, Sapphire/Granite Rapids, Zen 4/5), builds for
those targets also run the fixed-exponent powerings of all 16 lanes in AVX-512 registers,
8 lanes per register, and add up the curve points of eight scalar multiplications at once.
The miner's startup lines say which paths it took.

## Window and startup cost

`-a bc3hash:W` sets the curve table window, W in 10..20, default 16. The window
changes **table granularity only**: digests are identical at every W, which the
startup known-answer test confirms by passing at both 10 and 16.

| W | Tables | Rough build cost |
|---|---|---|
| 10 | 6 MB | fast |
| 16 | 256 MB | ~1.3 s (i7-7700K), ~7 s (RK3588S) |
| 20 | 3.1 GB | ~16 times window 16 (not measured) |

Floor 10 is the reference's own compact setting, below which the table count grows
while each digit still costs one scalar multiplication — the build gets cheaper and
mining gets slower. Ceiling 20 is a memory limit, not a consensus one.

The tables are one shared read-only copy for the whole process, so thread count does
not change their memory footprint and the miner's per-thread workspace auto-cap does
not apply to them.

## Implementation notes

The EC arithmetic is libsecp256k1's, not new code. `algo/bc3hash/bc3hash-ec.c` includes
the field and group internals of a recent libsecp256k1 (vendored under
`algo/bc3hash/secp256k1`, headers only) and owns just the call sequence: each scalar
multiplication is a sum of table points with variable-time additions, and the four
multiplications of a 256-bit round go Jacobian-to-affine together, sharing one
variable-time inversion. The public API would pay a constant-time inversion plus a
serialize per multiplication. All of it is public hash data, so variable time is fine.

The older libsecp256k1 that [curvehash](curvehash.md) vendors stays linked as the
kernel's **startup oracle**: it recomputes k*P for all four base points with its own
scalar multiplication, independent of the tables and of the kernel. The two must agree
on edge-case scalars (1, n-1, n, n+1, 2^256-1, ...), random scalars, and scalars that put
one digit value in every table row at once, or the algorithm refuses to register.

The five standard primitives are also not new code. The vendored reference carried
its own from-scratch SHA3/SHA-512/RIPEMD-160/BLAKE2s/BLAKE2b; those are dropped and
the tree's own libraries are used instead:

| Primitive | Source |
|---|---|
| SHA3-512/384/256 | `algo/keccak/sph_keccak.c`, `hard_coded_eb = 6` |
| SHA-512 | `algo/sha/sph_sha2big.c` |
| RIPEMD-160 | `algo/ripemd/sph_ripemd.c` |
| BLAKE2s + PERSONAL | `algo/blake/sph-blake2s.c` |
| BLAKE2b + PERSONAL | `algo/blake/sph_blake2b.c` |

Personalization is applied by `bc3_blake2b_init_pers` / `bc3_blake2s_init_pers` in
`algo/bc3hash/bc3hash-impl.h`, following the same convention as
`algo/equihash/equihash-impl.h`: `static inline` over the pristine libraries, never an
edit to them. Both are vendored and shared with argon2d, yespower and equihash.

What remains derived from the coin — `bc3hash-core.cpp`, `bc3hash-uint.hpp`,
`bc3hash-constants.hpp` — is the part with no analogue in this tree: the 256-bit field
arithmetic, the round constants, and the curve tables. Source commit, what was removed
and what was changed: `algo/bc3hash/VENDOR.md`.

## Verification

A known-answer test runs at startup and **registration fails on mismatch**, so a
divergent build cannot mine at all. It has four vectors: mainnet blocks 64360 (the
first BC3Hash block) and 64551, whose 80-byte headers must reproduce the published
block hashes, and two of the coin's own header vectors, covering version bit 11 alone
and bits 11 and 12 together. A nonce-flip check makes sure the hash depends on its input.

Those vectors are load-bearing rather than a formality, because every reused primitive
sits on a boundary that a wrong choice still survives: a Keccak pad (`0x01`) instead
of SHA3 (`0x06`), a RIPEMD-160 digest stored big-endian, or a BLAKE2 PERSONAL field
XORed into the wrong state words all produce a well-formed 32-byte digest that only a
verifier would reject.

End-to-end confirmation is pool-accepted shares: 275 submitted, 275 accepted, 0
rejected, at zpool `bc3hash` on 2026-10-16 from an aarch64 build (RK3588S, 8 threads),
over 45 minutes, 43 jobs and blocks 64625 to 64628, plus 163 of 163 from an x86-64
build (i7-11700F, 8 threads) across blocks 64635 to 64638. The stratum targets of the
two runs span 62x, and at every target the lowest accepted share sat within 1.09x of
it, which confirms the target scale of 1.0.

## Possible optimizations (preview)

- The six pre-hashes all consume the same 80-byte header and this tree already has
  n-way SHA3, SHA-512, RIPEMD-160 and BLAKE2. Batching them across nonces is the
  front end; BC3Mix stays serial per nonce and dominates, so the gain is bounded by
  whatever fraction the pre-hashes actually cost.
- The scalar multiplications are fixed-base and already table-driven. A wider window
  is exactly what `-a bc3hash:W` buys; past 20 the build time is the blocker.
- Montgomery's trick across nonces is implemented (see above), for both the curve
  multiplications and the finalisation inversions.
