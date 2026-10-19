# Odocrypt

**Coin:** DigiByte (DGB) — one of its five multi-algorithm PoW slots
**Algorithm name:** `odo`
**Family:** self-mutating block cipher

```
./cpuminer -a odo -o stratum+tcp://<pool>:<port> -u <wallet> -p x
```

---

## Overview

Odocrypt is unusual: **the algorithm rewrites itself every 10 days.** It is a
substitution-permutation network (SPN) block cipher whose S-boxes, permutations,
rotations and round keys are all regenerated from an epoch key derived from the block
time. The design is deliberately FPGA-friendly but ASIC-resistant — an ASIC baked for
one epoch's cipher is useless once the cipher mutates, while an FPGA can simply be
reconfigured.

The proof-of-work hashes the 80-byte block header through the current epoch's cipher
and finalizes with Keccak, producing a 32-byte hash compared against the target.

## Structure

1. **Epoch key.** A 32-bit key selects the cipher's shape. It comes from the pool
   (the `odokey` stratum field) or is derived from the header timestamp, rounded down
   to the 10-day epoch boundary:

   ```
   key = nTime − (nTime mod 864000)      // 864000 s = 10 days
   ```

2. **Cipher tables.** From the key, a Knuth-style LCG (`OdoRandom`) deterministically
   generates a full set of tables: 40 small (6-bit) S-boxes, 10 large (10-bit)
   S-boxes, two P-box permutation networks, rotation constants, and 84 round keys.
   These are built **once per epoch** and cached.

3. **Encrypt.** The 80-byte header is run through the SPN for **84 rounds** of
   S-box substitution, bit permutation, rotation and round-key mixing, producing an
   80-byte ciphertext.

4. **Finalize.** The 80-byte ciphertext is placed into a 100-byte Keccak-p[800] state
   with a `0x01` separator byte at offset 80 (the rest zero-padded), run through
   **Keccak-p[800], 12 rounds**; the first 32 bytes are the PoW hash.

## Consensus details

- **Epoch key** must match the network's (see [Stratum protocol](#stratum-protocol)).
  Mining with the wrong epoch key produces a valid-looking but rejected hash.
- The cipher is the **forward (encrypt) path** of DigiByte Core's reference Odocrypt;
  every table-generation and round step matches it bit-for-bit.

## Stratum protocol

Odocrypt uses the standard Bitcoin-style Stratum flow (standard `mining.notify` /
`mining.submit`, 80-byte header, 32-bit nonce at header word 19) with **one
addition**: the epoch key.

- The pool sends the epoch key as a **top-level `odokey` field in the `mining.notify`
  message** — a sibling of the standard `params` array, not an element inside it. The
  rest of the notify is the ordinary sha256d-style job.
- If the pool omits `odokey`, the miner **derives the key from the header timestamp**,
  `nTime − (nTime mod 864000)` (the 10-day epoch boundary). Both sources must agree
  with the network; the pool-supplied value is authoritative when present.
- `mining.submit` is unchanged — the epoch key is implied by the job, not resubmitted.

## Performance

- **8-way on AVX-512.** Eight nonces are encrypted at once. The small (6-bit) S-box
  lookups are done in-register with an AVX-512VBMI byte permute (`permutexvar`); the
  large (10-bit) S-box lookups use AVX-512 gather. A scalar path covers other CPUs.
- **Per-epoch table build.** Because the cipher only changes every 10 days, the
  expensive table generation happens once and is reused for the whole epoch; the
  scan loop just runs the cached cipher.

## Verification

A known-answer test runs at startup and refuses to mine on mismatch; end-to-end
correctness is confirmed by pool-accepted shares.

## Possible optimizations (preview)

The 8-way AVX-512 path (with the in-register small-S-box permute) is implemented;
remaining candidates are:

- **Large-S-box gather** — the 10-bit (1024-entry) S-box lookups still go through
  AVX-512 gather, which is the dominant cost of the wide path. A gather-free scheme
  (e.g. paired `permutex2var` over the table halves) could lift it, though the
  1024-entry width makes this harder than the small-S-box case.
- **AVX2 lane path** — a 4-way implementation for CPUs with AVX2 but not AVX-512,
  bridging the gap between the scalar and 8-way paths.
- **NEON path** — a vectorized aarch64 implementation.
