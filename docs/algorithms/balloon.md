# Balloon

**Coin:** Mateable (MTBC)
**Algorithm name:** `balloon`
**Family:** memory-hard password hash (Boneh–Corrigan-Gibbs–Schechter, 2016) over SHA-256

```
./cpuminer -a balloon -o stratum+tcp://<pool>:<port> -u <wallet> -p x
```

---

## Overview

Balloon fills a buffer with a hash chain, then mixes it repeatedly: each block is
rewritten from its predecessor, its own old value, and a few pseudo-randomly chosen
earlier blocks. The dependency chain is sequential, which is what makes it memory-hard —
you cannot compute block *i* without having computed everything before it.

Mateable uses it with `s_cost = 128` (KiB) and `t_cost = 4`, i.e. a **128 KiB** working
buffer of 4096 32-byte blocks and 4 mixing rounds. Stratum is stock Bitcoin-style: an
80-byte header, 32-bit nonce, sha256d merkle root.

## Structure

The salt is the **first 32 bytes of the header**. All integers hashed are little-endian,
and one counter runs unbroken across all three phases.

```
buf[0]   = SHA256( LE64(ctr++) ‖ salt ‖ header[0..79] ‖ LE64(s_cost) ‖ LE32(t_cost) )
buf[i]   = SHA256( LE64(ctr++) ‖ buf[i-1] )                            i = 1 .. 4095

4 times, for i = 0 .. 4095:
    buf[i] = SHA256( LE64(ctr++) ‖ buf[i ? i-1 : 4095] ‖ buf[i]
                     ‖ buf[idx++] ‖ buf[idx++] ‖ buf[idx++] )

digest   = buf[4095]
```

Blocks are updated **in place**, so a neighbour already visited this round contributes
its new value and one not yet visited its old one.

The 32-byte result is the proof-of-work hash, compared against the target as raw
little-endian `uint32[8]` — there is no byte reversal.

### The index stream

The 49,152 block indices come from an AES-128-CTR keystream:

```
key    = SHA256( salt ‖ LE64(s_cost) ‖ LE32(t_cost) )     — only the first 16 bytes key the cipher
stream = AES-128-CTR( key, IV = 0 ) over zeros
idx[j] = LE64( stream[8j .. 8j+7] ) mod 4096
```

**It depends only on the salt, so it is nonce-independent**: the table is built once per
job and reused for every nonce mined against it. cpuminer-opt caches it per thread, keyed
on the 32 salt bytes, and rebuilds it when they change. This is consensus-critical, not an
optimization — reusing another job's indices produces a well-formed digest that a pool
rejects.

The AES-128 here is a plain portable implementation on purpose. At ~25k blocks per *job*
rather than per hash, hardware AES would buy nothing and would add a second
implementation to keep bit-identical.

## Performance

~57,000 SHA-256 compressions per hash over a buffer that fits in L2, so balloon is
**SHA-256-throughput-bound, not memory-bound**. Hardware SHA-256 (SHA-NI, ARMv8 SHA2) is worth
**~3×** and is the whole performance story; huge pages and prefetch do not apply at 128 KiB.

### WARNING: Use every logical CPU, or pin one thread per core

Balloon benefits from SMT (+54% on a single core), so on an SMT machine the right setting is
**`-t <all logical CPUs>`**. Measured on an i7-11700F (8 cores / 16 threads), Windows:

| config | h/s |
|---|---|
| `-t 8` | 776 |
| `-t 8 --cpu-affinity 0x5555` | 1204 |
| `-t 16` | **1570** |

`-t 8` looks like "one thread per core" and is not: **on Windows, logical CPUs 0-7 are four cores
plus their SMT siblings**, so a plain `-t 8` buys half the machine. Either use all threads, or pass
a mask that selects one logical CPU per core (`0x5555` here). Linux enumerates physical cores
first, so `-t 8` there does get eight cores — the same flag is not needed.

### ARM does well here

Balloon is a serial chain of small SHA-256 messages, so it is latency-bound, and ARMv8's SHA2
instructions do more per clock than x86's. On an RK3588S (NanoPi R6S) one **Cortex-A76 at 2.3 GHz
reaches 279 h/s, beating an i7-11700F core at ~4.8 GHz (240 h/s)**, and the cluster scales almost
perfectly:

| config | mask | h/s |
|---|---|---|
| A76 ×4 | `0xf0` | **2064** |
| **all 8 cores** | — | **2751** |

At 2751 h/s that ~15 W board **outruns the 65 W i7-11700F (1570 h/s) by 1.75×**, so balloon is one
of the algorithms where a small ARM machine is decisively the better miner.

On any CPU with hardware SHA-256, balloon hashes **two nonces at a time** through interleaved SHA
streams — the index sequence is shared, so both lanes read the same offsets and nothing is gathered.
Worth **1.82× on Cortex-A76**, but only 1.07× on the little A55s, whose 128 KiB L2 cannot hold two
lanes' working sets; that is why the whole-device gain is 1.55× rather than 1.8×. On x86 it is
**1.04–1.07×** — smaller because the pipeline is closer to saturated, but still a gain at every
thread count including `-t 16`. Build with `-DBALLOON_FORCE_1WAY` to compare.

Use **all cores** here: the little cluster is 98% additive and worth a third of the total, so
restricting to the big cores costs 32%.

WARNING: On a big.LITTLE board, **any thread count below the core count needs an affinity mask**. Threads
are assigned to the set bits of the mask in order, and cpu0-3 are the *little* cores — so an
unmasked `-t 4` runs entirely on A55s, and an unmasked `-t 1` reports half the real per-core rate.

### Why there is no n-way path

The index stream is nonce-independent, so several nonces could in principle be hashed in parallel
SIMD lanes with no gather. This was measured and **rejected**: the n-way path would be vectorized
SHA-256, which is an *alternative* to SHA-NI rather than an addition to it, and it is slower than
hardware SHA-256 per block. It could only pay on a CPU with no SHA extension at all.

## Verification

A known-answer test runs at startup and **refuses to mine on mismatch**. It checks three
layers so a failure localises: AES-128 against FIPS-197 C.1, then the index bitstream
(key + keystream across a counter-block boundary), then five full digests — four from an
independent implementation and one from a **real work unit whose share the pool
accepted**, which pins the parameters and the header assembly against the live chain.
