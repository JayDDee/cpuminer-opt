# curvehash — Pulsar (PLSR)

```
-a curvehash        (alias: -a curve)
```

Pulsar's elliptic-curve proof of work, and **the only public-key PoW in this miner**. Every other
algorithm here is a symmetric hash; this one spends essentially all of its time doing secp256k1
scalar multiplication.

## Read this first: expected speed

**~2.2–2.4 kH/s per thread**, so roughly **35–40 kH/s on a 16-thread desktop**. A single RTX 3060
does ~1.85 MH/s — about **500× a whole CPU**.

That is not a bug and not a misconfiguration. Eight fixed-base scalar multiplications per nonce
are the entire cost, and there is no SIMD trick that closes a 500× gap. This algorithm is
supported for coverage and correctness parity, **not because CPU mining it is competitive**.

Measured baselines (2026-08-08, both pool-confirmed):

| Machine | Threads | Total | Per thread |
|---|---|---|---|
| i7-11700F (8 cores / 16 threads, AVX-512) | 16 | 34.3 kH/s | 2.14 kH/s |
| RK3588S (4×A76 + 4×A55) | 8 | 8.42 kH/s | 1.05 kH/s |

**On big.LITTLE ARM, use all your cores.** Restricting an RK3588S to its four big cores gives
5.25 kH/s — the four little cores are worth another 60% on top. (Use `--cpu-affinity`; `taskset`
does not pin cpuminer's threads.) Note this differs from `minotaurx` on the same hardware, where
running all eight can exceed what a small power supply delivers; curvehash draws much less.

## The algorithm

```
phash = SHA256( header[0..79] )              # the 80-byte block header
repeat 8 times:
    pubkey = secp256k1_pubkey_create(phash)  # the digest IS the private key
    phash  = SHA256( 0x04 || X || Y )        # the 65-byte uncompressed pubkey
digest = phash
```

Per nonce: 9 SHA-256 hashes and 8 scalar multiplications. The SHA-256 is ~1% of the work.

The eight rounds are **strictly serial** — each public key feeds the next hash — so there is no
parallelism *within* a nonce, only across nonces. That is why this is a 1-way implementation.

## What Pulsar is

Pulsar is a Bitcoin/Peercoin fork with two properties worth knowing:

- **Dual proof-of-work.** Blocks are either `curvehash` or `minotaurx`, selected by
  `(nVersion >> 16) & 0xFF`. This miner supports both, on separate pool ports.
- **Hybrid PoW/PoS.** Some blocks are minted by staking rather than mining. Those are not
  something a miner competes for, and they use their own difficulty scale — so a "Pulsar
  difficulty" quoted without saying which kind of block it refers to is meaningless.

Header handling is otherwise stock: 80 bytes, nonce at word 19, sha256d merkle root, generic
stratum, `opt_target_factor` 1.0.

## Correctness

The miner refuses to start if its startup self-test fails. That test covers three vectors:

- a synthetic header (bytes `00 01 … 4f`), whose expected digest was produced by an independent
  pure-Python secp256k1 implementation sharing no code with the library the miner links;
- **two real mainnet blocks** (7720014 and 7720015). Each is checked twice over — the header must
  reproduce the block id published by the chain under sha256d, *and* its curvehash digest must
  fall under the block's own difficulty target.

Pool-confirmed on zpool `curve` on 2026-08-08: 6 shares accepted, 0 rejected, across three block
changes.

## Implementation notes

The EC arithmetic is a vendored copy of **libsecp256k1** (MIT, compatible with this project's
GPLv2), built as a single translation unit under `algo/curvehash/`. On 64-bit targets it uses
64-bit limbs plus x86-64 assembly where available, falling back to 32-bit limbs elsewhere; all
configurations are cross-checked against each other and against the Python oracle.

One shared read-only signing context serves every mining thread. `secp256k1_ec_pubkey_create`
does not mutate it, and giving each thread its own would duplicate a precomputed table for no
benefit.

If a round ever produced an invalid private key (a digest of zero, or one at/above the group
order), that nonce is skipped rather than submitted. The chance is about 2⁻¹²⁸, and the Pulsar
daemon asserts it cannot happen in a valid block.
