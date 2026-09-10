# NeoScrypt / neoscrypt-xaya

**Coins:** Feathercoin, GoByte and others (`neoscrypt`); Xaya (CHI) and
SpaceXpanse (ROD) (`neoscrypt-xaya`)
**Algorithm names:** `neoscrypt`, `neoscrypt-xaya`
**Family:** memory-hard (Salsa20 + ChaCha20 + BLAKE2s), N=128, r=2

```
./cpuminer -a neoscrypt      -o stratum+tcp://<pool>:<port> -u <wallet> -p x
./cpuminer -a neoscrypt-xaya -o stratum+tcp://<pool>:<port> -u <wallet> -p x
```

---

## Overview

NeoScrypt is a memory-hard function in the scrypt lineage: a PBKDF2-BLAKE2s
prehash, a `SMix` core mixing Salsa20/8 and ChaCha20/8 over a 128 KiB buffer,
then a final PBKDF2. The hash itself is identical for both algos here; only the
header differs.

Difficulty follows the scrypt convention — difficulty-1 is ~65536 expected
hashes, not Bitcoin's 2^32 — so `opt_target_factor` is 65536 for both.

## neoscrypt-xaya

Xaya's proof-of-work does **not** hash its own block header. It hashes a
separate 80-byte "fake" header whose merkle-root field commits to the real
block, which lets one chain carry several mining algorithms:

```
fake header:  nVersion=0 | hashPrevBlock=0 | hashMerkleRoot = real block hash
              | nTime | nBits | nNonce
```

Consensus constrains only `hashMerkleRoot`; the rest is the pool's choice.
NeoScrypt is stand-alone only — Xaya rejects it merge-mined.

Three things follow, and all three are easy to get wrong:

1. **The real header arrives in the coinbase fields.** The pool sends a zero
   prevhash, an empty coinbase-part-2 and an empty merkle branch, with the real
   header as coinbase-part-1; extranonce2 is 2 bytes, so
   `coinb1 + xn1 + xn2` is exactly 80. The ordinary merkle step then already
   produces the real block hash.
2. **The merkle words take an extra byte swap** relative to every other coin.
3. **Every 32-bit word of the header, the nonce included, is byte-swapped on
   the way into the hash.** The pool assembles the header as hex and reverses
   the bytes within each word before hashing; a miner that hashes its work
   buffer directly computes a valid-looking hash that is rejected as invalid.

Because only `hashMerkleRoot` is checked by consensus, a wrong choice for the
other fields is not a consensus error — it simply disagrees with the pool, and
the symptom is a 100% reject rate rather than an error message.

## Verification

`neoscrypt-xaya` self-tests at startup against Xaya's mainnet genesis, whose
fake header is fully determined by `chainparams.cpp` (nNonce 482087,
nBits `0x1e0ffff0`, and the asserted block hash it commits to). The vector is
useful because the digest has to clear that block's own nBits: of the candidate
byte-order constructions, only one does.

`neoscrypt` has no startup vector; it is exercised by pool-accepted shares.

## Performance

- The `SMix` core is the whole cost; the BLAKE2s prehash is negligible.
- x86-64 uses hand-written assembly for the Salsa/ChaCha mixers
  (`asm/neoscrypt_asm.S`, selected by `USE_ASM`); other architectures compile
  the portable C path with `-DNOASM`.
- 128 KiB per hash keeps the working set in L2, so throughput scales with cores
  until memory bandwidth binds.
