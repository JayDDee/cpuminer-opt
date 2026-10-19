# Mike

**Coins:** VKAX, FortuneBlock (FTB)
**Algorithm name:** `mike`
**Family:** GhostRider variant (chained core hashes + CryptoNight)

```
./cpuminer -a mike -o stratum+tcp://<pool>:<port> -u <wallet> -p x
```

---

## Overview

Mike is GhostRider with a smaller core-algorithm pool: **11 instead of 15**. Because the
chain consumes that pool in groups of five, the third group shortens from five rounds to
one, giving 14 steps instead of 18:

```
gr     5 core, CN, 5 core, CN, 5 core, CN     (15 core + 3 CN)
mike   5 core, CN, 5 core, CN, 1 core, CN     (11 core + 3 CN)
```

Everything else matches GhostRider exactly, so this implementation reuses `algo/gr/`
unmodified — the core hash table, all six CryptoNight-v1 variants and their parameters,
the CryptoNight finalization, and the nibble walk that derives both orders.

**Core pool (11):** blake512, bmw512, groestl512, jh512, keccak512, skein512, luffa512,
cubehash512, shavite512, simd512, echo512. Compared with GhostRider, hamsi, fugue, shabal
and whirlpool are absent — VKAX Core does not ship them at all.

**CryptoNight variants (3 of 6 used per hash):** dark (512 KiB), dark-lite (512 KiB,
lower half addressed), fast (2 MiB), lite (1 MiB), turtle (256 KiB), turtle-lite
(256 KiB, lower half addressed).

Both orders are derived from the block header's **prevhash region, bytes [4, 36)**. The
digest is the low 32 bytes of the final CryptoNight output; there is no extra hash after
the chain. The merkle root is standard sha256d.

> **Selection detail that matters.** The core order is a permutation of 0..10 obtained by
> reducing each header nibble **`% 11`**. It is *not* GhostRider's 15-wide permutation
> truncated to 11 entries — the two disagree on almost every real block.

## Performance

Because the order depends only on the prevhash and not on the nonce, four nonces share a
rotation and are batched through the interleaved `cryptonight_4way` engine, which hides
scratchpad latency. That is worth about **1.99x** over the single-nonce path.

Mike does 4 fewer core hashes than GhostRider but the same three CryptoNight rounds, and
CryptoNight dominates the cost — so in practice **`mike` and `ghostrider` run at about the
same rate**, and mike responds to the same tuning.

CryptoNight is memory-latency bound and lives in L3. The 4-way path allocates
`4 x 2 MiB = 8 MiB` per miner thread, so `-t N` wants roughly `8 * N` MiB of cache.

> **Sweep the thread count on your own machine — it is the largest lever by far, and the
> right answer differs completely between CPUs.** Compare `-t 1` against your core count:
>
> - i7-7700K, **8 MiB** L3: 208 H/s at `-t 1`, 207 H/s at `-t 8`. Eight times the CPU for
>   nothing — one thread's working set already fills that L3.
> - RK3588S, **3 MiB** L3: 24 H/s at `-t 1` rising to 130 H/s at `-t 8`. Nothing fits at any
>   thread count, so extra cores keep helping.
>
> Take the peak of `-t 1,2,4,8`. Do not assume more threads is better, or worse.

Huge pages are used automatically when available.

Measured (i7-7700K and NanoPi R6S on otherwise idle machines; the i7-11700F rows are
indicative only, taken on a loaded desktop):

| Box | Build | Threads | H/s |
|---|---|---|---|
| i7-7700K (4C/8T, 8 MiB L3) | `-march=native` (AVX2+AES) | **1** | 208 |
| i7-7700K | `-march=native` | 8 | 207 |
| i7-11700F (8C/16T, 16 MiB L3) | `-march=native` (AVX-512) | 1 | ~160 |
| i7-11700F | `-march=native` | 16 | ~320-355 |
| i7-11700F | `-march=westmere -maes` | 1 | ~165 |
| i7-11700F | `-march=x86-64` (no SIMD, soft AES) | 1 | ~31 |
| NanoPi R6S (RK3588S, 3 MiB L3) | `armv8-a+crypto` | 4 (A76 only) | ~98 |
| NanoPi R6S | `armv8-a+crypto` | **8 (all cores)** | **~130** |

Hardware AES is the other big factor: the no-AES build is roughly **5x slower**.

On a big.LITTLE ARM SoC, use **all** the cores — on the RK3588S the four A55s add about 33%
over the A76 cluster alone. But if you run fewer threads than cores, pin them to the big
cores (`--cpu-affinity 0xf0` there), or the scheduler will scatter them and cost ~38%.
Note `taskset` does **not** work for this — cpuminer sets its own affinity mask.

`mike` and `ghostrider` run at nearly identical rates (mike measures ~0.5% ahead), so tuning
advice for one applies to the other.

## Correctness

`-a mike` runs a hard-fail self-test at startup; the miner refuses to run if it fails.
It checks two independent things:

1. **xmrig's `test_output_gr_mike[256]`** — 16 hashes across two rotations, XOR-compared.
   Note this vector alone is *not* sufficient: its inputs are nearly all zero, so it
   passes even with the wrong core-algo count.
2. **Four dense-prevhash vectors** generated from VKAX Core's own `Mike()`. These pin the
   `% 11` selection, and each one also runs four lanes through both the 1-way and 4-way
   paths and requires them to agree — so it doubles as the batching differential.

Digests are bit-identical across every build variant tested (plain x86-64, SSE2, SSE4.2,
SSE4.2+AES, AVX-512, and aarch64 with the ARMv8 crypto extension).

End-to-end consensus is confirmed on a live pool for **both coins**, with the same binary:
**52 shares accepted, none rejected** (1 stale from a job change in flight) — FortuneBlock
at block 412976 and VKAX at blocks 783529–783534, on zpool (2026-08-25).
