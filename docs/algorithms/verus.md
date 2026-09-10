# VerusHash 2.2

**Coin:** Verus Coin (VRSC)
**Algorithm name:** `verus`
**Family:** Haraka512 Merkle–Damgård chain + a self-modifying carryless-multiply hash

```
./cpuminer -a verus -o stratum+tcp://<pool>:<port> -u <wallet>.<worker> -p x
```

---

## Overview

VerusHash 2.2 is deliberately hostile to fixed-function hardware. Two stages:

1. **`VerusHashHalf`** — a Haraka512 Merkle–Damgård chain absorbs the 1472 job-constant
   bytes of the 1487-byte preimage. Job-dependent only, so it runs once per job.
2. **`verusclhashv2_2`** — 32 rounds over an 8832-byte key derived from the half-state,
   each round selected by the accumulator itself (an AES round, a carryless multiply, a
   64-bit modulo, or a variable-length inner loop). Rounds **mutate the key as they read
   it**; a journal of up to 64 changed slots restores it after every nonce. The final
   Haraka512 takes its round constants from the mutated key at a data-dependent offset.

The last stage is truncated to digest bytes 28..31 — the whole target test. Candidates are
re-hashed in full so the submitted digest is complete.

The wire format is Equihash 200/9's (140-byte header, 32-byte nonce field, 1344-byte
solution) and is shared with it in the code. **PBaaS headers submit a zeroed `nNonce`**, the
real nonce living in the solution's last 15 bytes; pools reject anything else.

## Instruction requirements

The inner loop needs an AES round, a 64×64→128 carryless multiply, and `_mm_mulhrs_epi16`.

| Target | AES round | Carryless multiply |
|---|---|---|
| x86-64 | AES-NI (`-maes`) | PCLMULQDQ (`-mpclmul`) |
| aarch64 + ARMv8 crypto extension | `AESE`+`AESMC` | `PMULL64` |
| aarch64 without it | emulated in NEON | emulated in NEON |

x86-64 without AES-NI and PCLMULQDQ refuses to register the algorithm. **aarch64 always
works**: cores lacking the crypto extension (Cortex-A53/A72 — Pi 3 and Pi 4, RK3328,
Allwinner H5/H6) use bit-exact emulations in `simd-utils/simd-neon-{aes,clmul}.h`.

### The emulated fallback, and what it costs

RK3588S, one core at a fixed clock, digests verified identical:

| core | hardware | emulated | |
|---|---|---|---|
| Cortex-A55 @ 1.8 GHz (in-order, like an A53) | 433 kH/s | **130 kH/s** | 3.3× slower |
| Cortex-A76 @ 2.3 GHz (out-of-order) | 923 kH/s | **333 kH/s** | 2.8× slower |

- **Expect about a third of the rate** of the same core with the extension. A Pi 3 (A53 @
  1.2 GHz) should reach ~85 kH/s per core, ~250–350 for four — a projection, not a measurement.
- Startup logs a warning naming the emulated primitive, so this is never silent.
- **If the CPU has the extension, emulating is a misconfiguration.** Use
  `-march=armv8-a+crypto` (Pi 4, RK3399) or `-march=armv8.2-a+crypto` (RK3588, Orange Pi 5);
  `armbuild-all.sh` builds both. WARNING: **With clang, `-march=native` does not enable the crypto
  extension** (gcc's does) — use `-mcpu=native` or spell out `+crypto`.
- **A 64-bit OS is required**: the NEON layer is `__aarch64__`-only, so armhf is out.
- Still far ahead of the alternative: the scalar software-AES path is ~4–5× worse again.

## Two nonces at once, on aarch64

On aarch64 the miner hashes **two nonces at a time**, interleaving their clhash iterations so
one nonce's stalls are filled with the other's work. Automatic; costs a second 9856-byte key
per thread. Off on x86-64, where hyperthreads already supply that parallelism.

Whole miner, every core busy:

| | 1 nonce | 2 nonces | |
|---|---|---|---|
| RK3588S, A76 cluster (`-t 4 --cpu-affinity 0xf0`) | 3650 kH/s | **4197** | **+15.0%** |
| RK3588S, A55 cluster (`-t 4 --cpu-affinity 0x0f`) | 1744 kH/s | 1746 | +0.1% |
| RK3588S, all 8 cores | 5356 kH/s | **5804** | **+8.4%** |
| i7-11700F, `-t 16` | 12.0 MH/s | 11.1 | −7.6% → **off** |

WARNING: **Single-core benchmarks give the wrong answer here** — isolated, the A76 gain is only
7% and the A55 shows a 7% *loss*. Load every core before concluding anything.
`FORCE_VERUS_1WAY` / `FORCE_VERUS_2WAY` override the choice at build time; the verification
harnesses cover both paths either way. **To see which path a binary uses, run with `-D`:**

```
VerusHash: clhash path 2 nonces interleaved (aarch64 default)
```

## Threads and affinity — worth more than any code tuning

| machine | use | got | a plausible wrong choice |
|---|---|---|---|
| i7-11700F (8C/16T) | **`-t 16`** | ≈12.9 MH/s | `-t 8` → 7.1–9.0 (**−30 to −40%**) |
| NanoPi R6S (4×A76 + 4×A55) | **`-t 8`** | ≈5.9 MH/s | `-t 4 --cpu-affinity 0xf0` → 4.2 (**−29%**) |

- **Use every logical CPU.** SMT is worth 30–40%, and the little cores are genuinely
  additive: the four A55s supply ~30% of the R6S total, losing only ~5% of their standalone
  rate while the big cores are busy.
- WARNING: **Cutting threads without an affinity mask is worse than it looks.** Thread N maps to the
  Nth *set bit* of the mask and cpu0-3 are the A55s, so `-t 4` alone runs entirely on the
  little cores: ≈1.75 MH/s, under a third of `-t 8`.
- **Do not carry over CryptoNight/minotaur affinity advice.** Pinning to the big cluster suits
  `minotaurx`, whose power draw browns out a weak PSU at `-t 8`; VerusHash runs all eight
  cores stably at ~50 °C and pinning costs ~29%.

## Difficulty numbers

Verus reports difficulty against its own `powLimit` of `0x0f0f…0f` = 2²⁵⁶/17, not Bitcoin's
difficulty-1 target, so every difficulty the miner prints — net, stratum target, per-share —
is scaled by `2^48 / (17 × 0xffff)` ≈ 2.5265e8 (`VRS_DIFF_SCALE`). Calibrated against mainnet
block 4174000 (`nBits 0x1b04b619` → 13910.1174 in Bitcoin units, chain publishes
3514376906066.49, reproduced to 6e-8) and confirmed live: mining block 4175285 the miner
printed `Net 2.80T` against the chain's 2795942602001. Unscaled it reads 11066.

Display only — Verus takes its share target verbatim from `mining.set_target`, so this
cannot affect share validity.

## Verification

The startup self-test is a **real-block known-answer test**: `algo/verus/verus-kat.h` holds
mainnet block 4174000 as the chain serializes it, and the test reproduces its published
hash. For a PBaaS header the published block hash *is* the canonical PoW hash, so one block
pins the whole chain, the canonical field clearing and the 15-byte nonce placement at once.
Two invariants ride along: the truncated Haraka writes only bytes 28..31, and the journal
restores the key to pristine after every hash.

On an emulated build the self-test first checks each primitive against an independent scalar
reference over ~4100 vectors plus the all-zero / all-ones / `0x80` edge cases, so an
emulation bug is reported as one rather than as a digest mismatch. **The miner refuses to
mine if any of this fails.**

Pool-accepted shares confirm x86-64 and aarch64 with hardware AES, on both the 1-nonce and
2-nonce paths (zpool, `-t 8` on an RK3588S: 103 then **112 accepted, 0 rejected, 0 stale**,
the latter at a live 5852 kH/s matching the benchmark). Not yet pool-confirmed: the emulated
path on a device that actually lacks the crypto extension.
