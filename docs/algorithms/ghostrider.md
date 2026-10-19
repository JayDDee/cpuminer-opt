# GhostRider

**Coin:** Raptoreum (RTM)
**Algorithm name:** `ghostrider` (also known as `gr`)
**Family:** CryptoNight-family chain

```
./cpuminer -a ghostrider -o stratum+tcp://<pool>:<port> -u <wallet> -p x
```

---

## Overview

GhostRider is a chained, header-dependent hash designed to be CPU-friendly and
ASIC/GPU-resistant. It interleaves a sequence of fast "core" hashes with memory-hard
CryptoNight rounds; both the choice and the order of hashes are derived from the
block header. The result is a 32-byte proof-of-work hash compared against the target.

It is the closest relative of [Flex](flex.md) — the two share the same overall shape
(core hashes interleaved with CryptoNight) but differ in several consensus details
(see [Differences from Flex](#differences-from-flex)).

## Structure

1. **Selection.** A digit-walk over a fixed region of the block header (the previous
   block hash) selects an order of core hashes and a triple of CryptoNight variants.
   Because the selection reads the prev-block region and **not** the nonce, every
   nonce for a given block takes the same path — a property the implementation
   exploits for batching (see below).

2. **Core pool (15).** The x16 set without SHA:
   `blake, bmw, groestl, jh, keccak, skein, luffa, cubehash, shavite, simd, echo,
   hamsi, fugue, shabal, whirlpool` — all 512-bit.

3. **CryptoNight pool (6).** Six CryptoNight-v1 variants differing in scratchpad
   size and iteration count: `dark, darklite, fast, lite, turtle, turtlelite`.
   Three are chosen per hash.

4. **The chain.** Three groups, each of five core rounds followed by one
   CryptoNight round:

   ```
   [core ×5] → CN → [core ×5] → CN → [core ×5] → CN → 32-byte hash
   ```

   The first core round consumes the full 80-byte header; every later round
   consumes 64 bytes. After each CryptoNight round the high 32 bytes of the working
   buffer are zeroed.

## Consensus details

- **CryptoNight variants** use the standard finalization: the extra hash is selected
  from `{blake, groestl, jh, skein}` by `state[0] & 3`, producing a 256-bit digest.
  The six variants' scratchpad sizes, iteration counts, and "lite" half-scratchpad
  addressing match the reference consensus miner.
- **Target handling** applies the GhostRider target factor (`65536`).
- The core and CryptoNight orders depend only on the prev-block region of the header,
  so they are computed once per block and reused across all nonces.

## Performance

GhostRider is one of the more heavily optimized algorithms in the project:

- **4-way nonce batching.** Because all nonces in a block share the same hash order,
  four nonces are pushed through the three CryptoNight stages together, interleaving
  their scratchpad accesses to hide memory latency.
- **Hardware CryptoNight.** The CryptoNight rounds use AES-NI, backed by per-thread
  scratchpads allocated on huge pages where the OS allows it.
- **Fast core hashes.** AES-NI Groestl/Echo and SSE2 Luffa/Cubehash, with the
  remaining cores from optimized implementations that are bit-identical to the
  reference.

## Verification

A built-in known-answer test runs at startup and refuses to mine on mismatch. The
CryptoNight core matches the authoritative cn/v1 test vector, the selection and
chain match the reference, and the six CryptoNight parameter sets match the
consensus miner; end-to-end correctness is confirmed by pool-accepted shares.

## Differences from Flex

| | GhostRider | [Flex](flex.md) |
|---|---|---|
| Core pool | 15 (includes JH) | 14 (no JH) |
| Selection seed | prev-block header region (nonce-independent) | `keccak512(header)` (nonce-dependent) |
| After each CN round | high 32 bytes zeroed | not zeroed |
| Final step | last CN output | extra `keccak256` |
| Keccak padding | standard | SHA-3 domain byte |
| CN finalization | `{blake,groestl,jh,skein}` by `& 3`, 256-bit | `{blake,groestl,skein}` by `& 2`, 512-bit skein |
| Nonce batching | 4-way (shared order) | 1-way (per-nonce order) |

## Possible optimizations (preview)

GhostRider is already well optimized; remaining candidates are incremental:

- **Wider batching on AVX-512** — extend the 4-way CryptoNight path to 8-way on CPUs
  with enough memory bandwidth and cache.
- **VAES CryptoNight** — use vectorized AES (VAES) for the CryptoNight AES rounds on
  supporting CPUs.
- **AVX-512 core hashes** — apply the project's widest core-hash implementations to
  the core rounds.
