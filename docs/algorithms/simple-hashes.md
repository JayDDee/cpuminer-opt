# Simple & legacy hashes

**Family:** single-hash and short fixed-chain proof-of-work algorithms
**Algorithm names:** `sha256d`, `sha256t`, `sha256q`, `sha256dt`, `sha256csm`, `sha512256d`,
`sha3d`, `keccak`, `keccakc`, `k12`, `blake`, `blakecoin`, `vanilla`, `blake2s`, `blake2b`,
`pentablake`, `bmw`, `bmw512`, `groestl`, `dmd-gr`, `myr-gr`, `skein`, `skein2`,
`whirlpool`, `whirlpoolx`, `whirlpoolx2`, `nist5`, `quark`, `qubit`, `anime`

```
./cpuminer -a sha256d -o stratum+tcp://<pool>:<port> -u <wallet> -p x
```

---

## Overview

These are the conventional algorithms: one well-known hash applied once or a few
times, or a short fixed chain of a handful of hashes. They predate the long X-chains
and the memory-hard designs, and they all use the standard Bitcoin-style Stratum flow
(80-byte header, 32-bit nonce). Because they are mostly a single primitive, they are
the most thoroughly SIMD-optimized algorithms in the project.

## SHA-2 / SHA-3 lineage

| Algo | Definition | Notes |
|---|---|---|
| `sha256d` | SHA-256 applied twice | Bitcoin's algorithm |
| `sha256t` | SHA-256 applied three times | |
| `sha256q` | SHA-256 applied four times | |
| `sha256dt` | double SHA-256 with a **custom initialization vector** | |
| `sha256csm` | double SHA-256 where the first hash covers the 80-byte header **zero-extended to 112 bytes** | Galleoncoin (GALE), aliases `gale`, `galleon` — see [SHA256csm](sha256csm.md) |
| `sha512256d` | double SHA-512/256 (SHA-512 truncated to 256 bits) | |
| `sha3d` | double Keccak-256 (SHA-3 padding) | BSHA3 |
| `sha3t` | triple SHA3-256 | BitcoinIII (BC3), Fjarcode (FJAR) — see [SHA3T](sha3t.md) |

(Veil's `sha256dv` is a SHA-256d variant with its own Stratum protocol — see
[SHA256Dv](sha256dv.md).)

WARNING: `sha3d` and `sha3t` differ by more than the round count: `sha3d` builds the Stratum
merkle root with `sha3d`, `sha3t` uses the ordinary `sha256d`. See [SHA3T](sha3t.md).

## Keccak

| Algo | Definition | Coin |
|---|---|---|
| `keccak` | Keccak-256 | Maxcoin |
| `keccakc` | Keccak-256 (SHA-3 padding variant) | Creative Coin |
| `k12` | KangarooTwelve, 32-byte output, no customization string | |

`k12` is Keccak-p[1600,12] under the KangarooTwelve tree construction, not a Keccak-256
round-count variant. The same primitive hashes the seed inside `panthera`.

## BLAKE

| Algo | Definition | Coin |
|---|---|---|
| `blake` | BLAKE-256, 14 rounds | |
| `blakecoin` | BLAKE-256, 8 rounds | |
| `vanilla` | BLAKE-256, 8 rounds (vanilla variant) | VCash |
| `blake2s` | BLAKE2s-256 | |
| `blake2b` | BLAKE2b-512 | |
| `pentablake` | BLAKE-512 applied five times | Pentablake |

## Groestl

| Algo | Definition | Coin |
|---|---|---|
| `groestl` | Groestl-512 | Groestlcoin |
| `dmd-gr` | Diamond-Groestl | Diamond |
| `myr-gr` | Groestl-512 + SHA-256 ("Myriad-Groestl") | Myriad |

## Skein / BMW / Whirlpool

| Algo | Definition | Coin |
|---|---|---|
| `skein` | Skein-512 + SHA-256 | Skeincoin |
| `skein2` | Skein-512 applied twice | Woodcoin |
| `bmw` | BMW-256 | |
| `bmw512` | BMW-512 | |
| `whirlpool` | Whirlpool | |
| `whirlpoolx` | Whirlpool variant | |
| `whirlpoolx2` | one Whirlpool-512 over the header, folded 512 -> 256 bits | CapStash (CAP) |

### whirlpoolx2 vs whirlpool / whirlpoolx

Despite the name, `whirlpoolx2` applies Whirlpool **once**:

```
out[i] = wh[i] ^ wh[i+32],  i < 32     where wh = Whirlpool512(80-byte header)
```

The "x2" is the 512 -> 256 halving, not a second pass. The three algorithms are easy to
confuse, so in full:

| | primitive | fold offset |
|---|---|---|
| `whirlpool` | Whirlpool-1 (2001 revision), 4 passes | none, truncates to 32 bytes |
| `whirlpoolx` | Whirlpool-1 (2001 revision) | 16 |
| `whirlpoolx2` | plain Whirlpool (ISO/IEC 10118-3 final) | 32 |

At startup the miner reproduces the four CapStash genesis blocks
(mainnet/testnet/signet/regtest), which were mined at nBits `0x1d01fffe` against this
construction, and refuses to run if any digest fails to clear its own target.
`opt_target_factor` is `1.0`: CapStash compares the digest to nBits directly as a
little-endian uint256. The Stratum merkle root is the ordinary `sha256d` one.

Pool-confirmed on x86-64 and aarch64 across many sessions: 335 accepted, 0 rejected, at
Stratum difficulties from 0.01 to 0.5.

Runs 1-way. Three optimizations apply, all bit-exact against the reference core, which the
miner re-checks over 512 nonces at every start:

- a cached Whirlpool midstate over the header's constant first 64 bytes (the nonce sits at
  bytes 76..79);
- the ten round keys expanded **once per job** rather than once per nonce -- Whirlpool is a
  block cipher keyed by the chaining state, and here that state is job-constant, so the key
  schedule was half the work of every nonce;
- only the two state words that decide the target comparison are computed in the final
  round, with the full digest produced only for a nonce that survives that screen.

### whirlpoolx2 tuning: SMT buys nothing here

On an SMT machine, one thread per physical core matches using every logical CPU. Measured on
an i7-7700K (4 cores / 8 threads), Linux:

| config | MH/s |
|---|---|
| `-t 4 --cpu-affinity 0xf` | 29.7 |
| `-t 8` | 29.9 |

The two are within run-to-run noise, so `-t 4` costs nothing and leaves half the machine free.
An RK3588S (4x A76 + 4x A55) reaches 22.8 MH/s using all eight cores -- on big.LITTLE use every
core, the little ones still contribute.

NOTE: this is the opposite of `balloon`, which gains ~54% from SMT. Thread advice does not carry
between algorithms; measure per algorithm. `--cpu-affinity` is also the only mask that works --
`taskset` does not constrain cpuminer's threads.

## Short fixed chains

A handful of hashes in a fixed order — the small ancestors of the X-chains:

| Algo | Chain | Coin |
|---|---|---|
| `nist5` | blake, groestl, jh, keccak, skein (the 5 SHA-3 finalists) | |
| `quark` | blake, bmw, groestl, jh, keccak, skein with **data-dependent branching** (9 steps) | Quarkcoin |
| `qubit` | luffa, cubehash, shavite, simd, echo | Qubit |
| `anime` | a Quark variant with different branching | Animecoin |

## Performance

- **SHA-NI** for the SHA-256 algorithms, and wide multi-way SHA-256 (8/16-way on
  AVX2/AVX-512) for scanning many nonces per pass.
- **AES-NI / VAES** for Groestl rounds. Whirlpool's round shares AES's structure but uses a
  different S-box and MDS matrix, so it cannot use those instructions: `sph_whirlpool.c` is
  table-driven scalar C on every target, and the three `whirlpool*` algos run 1-way.
- **Parallel-lane hashing** (4/8/16-way) for the BLAKE, BMW, Keccak, Skein and
  short-chain algorithms.
- **Midstate caching** where the first hash's leading block is constant across nonces.

## Verification

Every SIMD width matches the scalar reference byte-for-byte; correctness is confirmed
by pool-accepted shares.

## Possible optimizations (preview)

These are mature and close to optimal. Remaining candidates are incremental:

- **Full AVX-512 / VAES coverage** — make sure every algorithm has the widest lane and
  hardware-AES path on capable CPUs.
- **Target prefilter** — for the multi-hash members (`sha256t/q`, `nist5`, `quark`),
  skip the remaining rounds once an intermediate value cannot meet the target.
