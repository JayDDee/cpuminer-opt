# X-chains (x11–x17 and relatives)

**Coins:** Dash (x11) and many others across the variants below
**Algorithm names:** `x11`, `x12`, `x13`, `x14`, `x15`, `x17`, `c11`, `x11evo`,
`x11gost`, `x13bcd`, `x13sm3`, `xevan`, `sonoa`, `hmq1725`, `x22i`, `x25x`
**Family:** fixed-order (or fixed-rule) chains of core hashes

```
./cpuminer -a x11 -o stratum+tcp://<pool>:<port> -u <wallet> -p x
```

---

## Overview

These algorithms run a sequence of well-known 512-bit hashes one after another, each
consuming the previous one's 64-byte output (the first consumes the 80-byte header),
the last output being the 32-byte PoW hash. Unlike the [x16r family](x16r.md) — where
the *order* is chosen by the header — the order here is **fixed** (or fixed by a
simple rule). They use the standard Bitcoin-style Stratum flow.

The shared building blocks are the "x" hash set:

```
blake, bmw, groestl, skein, jh, keccak, luffa, cubehash, shavite, simd, echo,
hamsi, fugue, shabal, whirlpool, sha512, haval
```

## The progressive core: x11 → x17

Each step extends the previous one by appending more hashes:

| Algo | Hashes | Sequence (added in **bold**) |
|---|---|---|
| `x11` | 11 | blake, bmw, groestl, skein, jh, keccak, luffa, cubehash, shavite, simd, echo |
| `x13` | 13 | …echo, **hamsi, fugue** |
| `x14` | 14 | …fugue, **shabal** |
| `x15` | 15 | …shabal, **whirlpool** |
| `x17` | 17 | …whirlpool, **sha512, haval256** |

`x11` is Dash's algorithm; the order shown is the consensus Dash order (note `skein`
precedes `jh`/`keccak`). `x12` is a 12-hash member of the same progression.

## Related fixed / rule-based chains

Same hash set, different fixed order or extra rounds:

| Algo | What it is | Coins |
|---|---|---|
| `c11` | The x11 hashes in a **different fixed order** | Chaincoin |
| `x11evo` | x11 with the order **permuted by block height/time** | Revolvercoin |
| `x11gost` | x11 with a **Streebog (GOST)** round | Sibcoin (`sib`) |
| `x13sm3` | x13 variant using **SM3** | Hshare (`hsr`) |
| `x13bcd` | x13 variant | Bitcoin Diamond (`bcd`) |
| `xevan` | the full x17 sequence run **twice** (over a 128-byte working buffer) | Bitsend (BSD) |
| `sonoa` | x17 applied in **escalating passes** (progressively longer sub-chains) | Sono |
| `hmq1725` | a 25-step chain with **data-dependent branching** (the next hash depends on a bit of the running value) | — |
| `x22i` | x17 plus extra rounds (SHA-256, Tiger, GOST, a Lyra2 step, …) and an integrating combine, 22 stages | — |
| `x25x` | a 25-stage chain | — |

(Header-*selected* chains — `x16r`, `x16s`, `x20r`, `x21s`, etc. — are covered in
[x16r and the X16 family](x16r.md). Short fixed chains such as `tribus` (jh, keccak,
echo) and the time-permuted `timetravel`/`timetravel10` belong to the same idea.)

## Performance

Because the chain is fixed and there is no memory-hard step, the X-chains parallelize
very well:

- **Parallel-lane hashing.** They ship multi-way implementations (4-way AVX2, 8-way
  and 16-way AVX-512), hashing several nonces per pass.
- **Hardware AES.** The AES-based rounds (Groestl, Echo, Shavite, Fugue) use AES-NI /
  VAES where available.
- **Constant first block.** The first hash's leading block covers the part of the
  header that doesn't change between nonces, so its state can be computed once per
  work item.

## Verification

Every SIMD width matches the scalar reference byte-for-byte; correctness is confirmed
by pool-accepted shares for each coin.

## Possible optimizations (preview)

- **Full AVX-512 lane coverage** — ensure every hash in the longer chains (x17, x22i,
  x25x) has a 16-way implementation so the wide path never narrows mid-chain.
- **VAES rounds** — vectorized AES for the AES-based hashes.
- **Early exit** — abandon a nonce as soon as an intermediate value rules out meeting
  the target, instead of always running the whole chain.
