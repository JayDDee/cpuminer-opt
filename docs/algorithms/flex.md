# Flex

**Coins:** Kylacoin (KCN), Lyncoin (LCN) and relatives
**Algorithm name:** `flex`
**Family:** CryptoNight-family chain (a GhostRider sibling)

```
./cpuminer -a flex -o stratum+tcp://<pool>:<port> -u <wallet> -p x
```

---

## Overview

Flex is a chained, header-dependent hash: it runs a sequence of 18 rounds over the
block header, mixing fast "core" hashes with memory-hard CryptoNight rounds. Both
the choice and the order of hashes are derived from the header itself, so the work
done varies from block to block (and, unlike GhostRider, from nonce to nonce).

The 32-byte result is the proof-of-work hash compared against the target.

## Structure

1. **Seed / selection.** `keccak512` of the 80-byte header produces a 64-byte seed.
   A digit-walk over the seed selects an order of core hashes and an order of
   CryptoNight variants (the same selection scheme GhostRider uses).

2. **Core pool (14).** The x16 set without JH and SHA:
   `blake, bmw, groestl, keccak, skein, luffa, cubehash, shavite, simd, echo,
   hamsi, fugue, shabal, whirlpool` — all 512-bit.

3. **CryptoNight pool (6).** Six CryptoNight-v1 variants differing in scratchpad
   size and iteration count: `dark, darklite, fast, lite, turtle, turtlelite`.

4. **The chain.** Three groups, each of five core rounds followed by one
   CryptoNight round:

   ```
   [core ×5] → CN → [core ×5] → CN → [core ×5] → CN → keccak256 → 32-byte hash
   ```

   The first core round consumes the full 80-byte header; every later round
   consumes 64 bytes. A final `keccak256` produces the output.

## Consensus details

These are part of Flex's network consensus — an implementation must match them
exactly or its shares are rejected:

- **Keccak padding** uses the SHA-3 domain byte (`0x06`), applied to every keccak
  in the chain (seed, the `keccak` core, the final hash) and to the merkle root.
- **Merkle root** is keccak-based: the coinbase transaction is hashed with `sha3d`
  (double `keccak256`), and merkle branches are then folded with `sha256d`.
- **CryptoNight finalization** selects from `{blake, groestl, skein}` (no JH) using
  `state[0] & 2`, and the skein leg produces a **512-bit** digest. This differs from
  GhostRider's finalization, so the two algorithms' CryptoNight cores are not
  interchangeable despite sharing variant names.

## Verification

The implementation carries a known-answer test taken from a live, pool-accepted
share. It runs once at startup; on mismatch the miner logs the computed and expected
digests and refuses to mine, so a broken build can never submit invalid shares.

## Implementation notes

Flex reuses the project's existing fast core hashes (AES-NI Groestl/Echo, SSE2
Luffa/Cubehash, and the rest) and a dedicated set of CryptoNight cores matching
Flex's consensus finalization. Because the hash order depends on the nonce, each
nonce takes an independent path through the chain.

## Possible optimizations (preview)

Currently correctness-first; the following are candidate speedups for future work:

- **Hardware CryptoNight cores.** Move the memory-hard rounds onto the project's
  AES-NI scratchpad engine (with persistent, huge-page-backed scratchpads) instead
  of per-call stack allocation — the CryptoNight rounds dominate Flex's runtime, so
  this is the largest available win.
- **Multi-nonce batching.** Hash several nonces concurrently to hide CryptoNight
  memory latency. Because Flex's variant order is nonce-dependent, this needs a
  per-nonce variant schedule rather than a single shared variant per stage.
- **Core-hash tuning.** Apply the wider AVX2/AVX-512 core implementations already
  used elsewhere in the project to the core-hash rounds.
