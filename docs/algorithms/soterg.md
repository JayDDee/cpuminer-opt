# SoterG

**Coin:** Soteria (SOTER)
**Algorithm name:** `soterg` (aliases `x12r`, `soter`)
**Family:** x16r-style variable-order cascade, 12 functions, time-derived order

```
./cpuminer -a soterg -o stratum+tcp://<pool>:<port> -u <wallet> -p x
```

---

## Overview

SoterG chains twelve 512-bit hashes in an order that changes with the block
time:

```
seed     = SHA256d( (int32) ( nTime & 0xFFFFFFA0 ) )
order[i] = rejection-sampled nibble of seed,  i = 0..11
h[0]     = f(order[0])( header80 )
h[i]     = f(order[i])( h[i-1], 64 bytes )
digest   = low 256 bits of h[11]
```

The twelve functions, in the order their ids are numbered:

| 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| BLAKE | SHABAL | GROESTL | JH | KECCAK | SKEIN | LUFFA | CUBEHASH | SIMD | ECHO | HAMSI | SHA512 |

Every one of them was already in this miner for the x11/x13/x16r families, so
the port adds no new cryptography.

## The order is per job, not per nonce

The seed comes from the timestamp alone, masked to a **96-second bucket**
(`0xFFFFFFA0`). The daemon's own comment explains the choice: a GPU needs
30-45 s to stabilise voltage and a CPU 15-25 s to load algorithms, so a 96-second
bucket gives three full switching cycles and measured the most stable hashrate.

Because the order does not depend on the nonce, it is resolved once per job and
the interleaved n-way paths remain usable — unlike an algorithm whose order
varies per nonce, which forces one lane at a time.

## Two details that are easy to get wrong

**The stage ids are not x16r's.** SoterG numbers SHABAL 1, SIMD 8, ECHO 9,
HAMSI 10 and SHA512 11, where x16r has them at 13, 9, 10, 11 and 15. The n-way
path reuses x16r's cascade, so it translates ids through a map; getting that map
wrong produces a plausible-looking digest that no pool will accept.

**The nibble walk is not x16r's either.** It reads nibbles 48..63 of the seed
and rejection-samples: a nibble below 12 is used directly, otherwise the next
fifteen positions are tried, and failing all of those the value is reduced
modulo 12. Real blocks exercise the fallback — the order at height 100 is
`644444444B99`, eight consecutive KECCAK stages.

## Soteria is a four-algorithm chain

The PoW function is chosen by version bits, not by the coin:

```c
POW_TYPE_NAMES[] = { "soterg", "soterc", "soterhash", "X8S" };
GetPoWType() { return (POW_TYPE)( ( nVersion >> 16 ) & 0xFF ); }
```

and further changes are gated on consensus timestamps. Live blocks carry type 0,
`soterg`, which is what this implements. `soterc` — the CPU-oriented algorithm —
is disabled on chain, and a `soterhash` upgrade is scheduled, after which blocks
of that type use a different function in the same family.

## Verification

`register_soterg_algo` runs a start-up self-test and **refuses to register** if
it fails, so a wrong build cannot mine.

**Five real mainnet headers**, heights 100 to 1,821,800, each with a different
derived order. This works as a known-answer test because the daemon's
`CBlockHeader::GetHash()` returns `ComputePoWHash()` — the SHA-256d of the
header is only a cache key — so a block's id *is* its PoW hash.

Each header is then run through the interleaved path with every lane carrying
that block's own nonce, and every lane must return the block's digest. That is
what checks the id translation and the lane plumbing; the scalar test alone
cannot. A non-vacuity check follows: flipping one nonce bit must change the
digest.

`opt_target_factor` is 1.0, the plain 256-bit convention.

## Implementation

| file | role |
|---|---|
| `algo/x16/soterg.c` | order derivation, scalar cascade, self-test, registration |
| `algo/x16/soterg-4way.c` | 8x64 / 4x64 / 2x64 paths, reusing x16r's cascade |
| `algo/x16/soterg-gate.h` | constants, stage ids, prototypes |
| `algo/x16/soterg-kat.h` | the real-block vectors |

The interleaved widths call `x16r_{8way,4way,2x64}_hash_generic` with a
translated order string and a function count of 12, so the whole interleaved
cascade and its prehash are shared with x16r rather than duplicated. Width
selection follows x16r's own: AVX-512 gives 8 lanes, AVX2 with AES 4, and SSE2
or NEON 2.

Note that those generics emit **64 bytes per lane**, not 32; x16r's own scanhash
reads a 32-byte stride only because it goes through the `x16r_8way_hash`
wrapper, which repacks first.

`sph_keccak512` selects its padding from the global `hard_coded_eb` — 1 for
Keccak, 6 for SHA3. This cascade needs Keccak, so registration pins it rather
than inheriting whatever the previously registered algorithm left behind.
