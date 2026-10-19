# SkyDoge

**Coin:** SkyDoge
**Algorithm name:** `skydoge`
**Family:** fixed-order chained hash (an X-family extension)

```
./cpuminer -a skydoge -o stratum+tcp://<pool>:<port> -u <wallet> -p x
```

---

## Overview

SkyDoge runs a fixed sequence of 20 well-known hashes, each consuming the previous
one's output. Like the [X-chains](x-chains.md), the order is fixed (it does not depend
on the header), so there is no branching and no memory-hard step — it is compute-bound
and parallelizes cleanly. It uses the standard Bitcoin-style Stratum flow (80-byte
header, 32-bit nonce, sha256d merkle root).

The 32-byte result of the final hash is the proof-of-work hash compared against the
target.

## Structure

20 stages. The first consumes the 80-byte header; every later stage consumes the
previous 64-byte output:

```
 1 blake512     2 skein512     3 bmw512      4 groestl512   5 jh512
 6 luffa512     7 keccak512    8 simd512      9 echo512     10 cubehash512
11 shavite512  12 hamsi512    13 fugue512    14 shabal512   15 whirlpool
16 sha512      17 simd512     18 whirlpool   19 sha256      20 haval256-5
```

Notes:
- `simd512` and `whirlpool` each run **twice** (stages 8 & 17, and 15 & 18).
- **Finalization:** stage 19 (`sha256`) writes a 32-byte digest into the low half of a
  64-byte buffer; the high 32 bytes are zeroed; stage 20 (`haval256-5`) then hashes the
  full 64-byte buffer. The first 32 bytes of its output are the result.

## Performance

Because the chain is fixed and nonce-independent, SkyDoge is compute-bound and
parallelizes cleanly:

- **Parallel-lane hashing.** AVX-512 hashes 8 nonces at once (8×64; the heavy hashes
  run 4×128), AVX2 hashes 4 (4×64; heavies 2×128); blake, skein, bmw, jh, keccak,
  hamsi and sha512 run at the full 64-bit lane width, luffa and the
  simd/echo/cubehash/shavite group run at half width (using VAES for the AES rounds
  where available), and shabal/sha256/haval run at the 32-bit lane width (8-way on
  AVX-512, 4-way on AVX2). Only fugue and whirlpool run per-lane — they have no n-way
  implementation. CPUs without AVX2 use a scalar path.
- **Hardware AES** (AES-NI / VAES / ARMv8 crypto) for the AES-based rounds — Groestl,
  Echo, Fugue.
- Every implementation (each SIMD width and the scalar reference) is bit-identical, so
  the startup KAT below guards all of them.

## Verification

A known-answer test runs at startup against a known `(header → hash)` vector and
**refuses to mine on mismatch**, so a miscompiled or divergent build can never submit
invalid shares. End-to-end correctness is confirmed by pool-accepted shares.

## Possible optimizations (preview)

- fugue and whirlpool are the only remaining per-lane stages on all paths; they have
  no n-way implementation in the codebase, so they bound further gains. Adding n-way
  fugue/whirlpool (or a 16-way path) is the only remaining lever, with diminishing
  returns.
