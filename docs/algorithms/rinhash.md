# RinHash

**Coin:** RinCoin (RIN)
**Algorithm name:** `rinhash` (alias `rin`)
**Family:** chained hash -> memory-hard KDF -> hash

```
./cpuminer -a rinhash -o stratum+tcp://<pool>:<port> -u <wallet> -p x
```

---

## Overview

RinHash chains three primitives, each of which this miner already shipped for
other algorithms:

```
digest = SHA3-256( Argon2d( BLAKE3( header80 ) ) )
```

RinCoin is a Litecoin-lineage chain (Bitcoin -> Litecoin -> RinCoin) with a
one-minute block target. The design intent is ASIC resistance: BLAKE3 is fast,
Argon2d is memory-hard, and SHA3-256 finalises to a standard 256-bit output so
existing PoW plumbing works unchanged.

Argon2d is deliberately small here -- 64 KiB, 2 passes -- which is enough to
frustrate a fixed-function pipeline but far below the multi-megabyte settings
that make an algorithm strictly CPU-friendly.

## Parameters

Taken from the daemon (`src/crypto/rinhash.cpp`), all of them consensus:

| Stage | Parameter | Value |
|---|---|---|
| BLAKE3 | input | the **serialized 80-byte block header** |
| | output | 32 bytes |
| Argon2d | password | the BLAKE3 output, 32 bytes |
| | **salt** | **`"RinCoinSalt"`, 11 bytes, fixed ASCII** |
| | `m_cost` | 64 KiB |
| | `t_cost` | 2 |
| | `lanes` / `threads` | 1 / 1 |
| | version | `0x13` (Argon2 1.3) |
| | type | Argon2**d** (data-dependent addressing) |
| | output | 32 bytes |
| SHA3-256 | input | the Argon2d output, 32 bytes |
| | padding | **`0x06` -- real SHA3, not Keccak's `0x01`** |

Two of these are the classic silent-divergence traps: the salt is a **fixed
string**, not the header, and the final stage is **SHA3, not Keccak**. Either
mistake produces a plausible-looking digest that no pool will accept.

## Digest byte order

The digest is consumed as a raw 256-bit little-endian value and compared
against the target the same way, with **no byte reversal** and no conversion to
the host-order `uint32[8]` layout most algorithms here use. `valid_hash()` is
therefore not usable; the comparison is a plain byte-wise compare from the most
significant end.

## Header byte order

BLAKE3 hashes the **serialized** header -- the same bytes that go on the wire --
so `scanhash` byte-swaps the work data first:

```c
v128_bswap32_80( edata, pdata );   // work->data words -> serialized header
edata[19] = n;                     // nonce as a host word
...
pdata[19] = bswap_32( n );         // swapped back when submitting
```

This is the same convention as `sha256q`, `megabtx` and every other algorithm in
this tree, and it is why the work data is not hashed directly.

> Note for anyone comparing against RinCoin's own miner fork: that fork hashes
> `work->data` unswapped, which works only because it also patches the shared
> `std_build_block_header` to pre-swap the version, prevhash and merkle root.
> That function serves every algorithm here, so the change is not portable and
> is not used.

## Verification

`register_rinhash_algo` runs a start-up self-test and **refuses to register** if
it fails, so a wrong build cannot mine.

**Seven real mainnet headers**, genesis through height 722000, spanning
difficulties `0x1f00ffff` to `0x1d06b097`. Each is asserted twice: the digest
matches the block's own hash exactly, *and* it is under that block's own nBits
target. The second assertion alone would accept a wrong-but-small digest; the
first alone would not exercise the target comparison.

These vectors need no separate PoW field, because RinCoin's
`primitives/block.cpp` defines **both** `GetHash()` and `GetPoWHash()` as
`RinHash(*this)` -- a block's hash *is* its PoW hash. Genesis alone would be
insufficient: its `hashPrevBlock` is all zeros and so cannot catch a prevhash
ordering error, which is why the set starts at height 1.

A non-vacuity check follows: flipping one nonce bit must change the digest.

**Pool-confirmed:** 3 accepted / 0 rejected / 0 stale on zpool, 16 threads, over two block
crossings (blocks 722720 to 722722), with share difficulties of 0.00119, 0.00112 and 0.00090
against a 0.0005 stratum target.

The digest is verified across five build configurations -- AVX-512, AVX2, SSE4.2, SSE2 and
native aarch64. That is cross-*implementation* agreement rather than cross-compilation:
Argon2d takes its AVX-512 path on the first and its 128-bit path on both SSE2 and NEON, and
BLAKE3 dispatches to a different kernel in each case.

`opt_target_factor` is **1.0**, derived rather than assumed. The chain uses the
standard Bitcoin difficulty-1 base, confirmed three ways: `nbits_to_diff`
matches the explorer's reported difficulty at five heights to ten decimal
places; the miner's own time-to-share forecast agrees with the naive
`diff * 2^32 / rate` arithmetic; and the observed share cadence on a live pool
matched that forecast.

## Performance

| | rate |
|---|---|
| 1 thread, i7-11700F, AVX-512 | ~33.6 kH/s |
| 16 threads, same machine | ~158-179 kH/s |

Argon2d at 64 KiB dominates, so throughput tracks memory bandwidth more than
core count: 16 threads on 8 physical cores give roughly 5x one thread. The
network was estimated at 57-77 MH/s during testing, so a machine of this class
is a small fraction of it -- the worker counts quoted for this algorithm on
pools are GPU and CPU combined.

## Implementation

`algo/rinhash/rinhash.c`, reusing three primitives already in the tree:

| Stage | Reused from |
|---|---|
| BLAKE3 | `algo/blake3/` (vendored for `hoohashv110`) |
| Argon2d | `algo/argon2d/argon2d/` (shared with six argon2 variants) |
| SHA3-256 | `sha3_256_prepad32()` in `algo/keccak/`, written for `heavyhash` |

No new cryptographic code and no new vendored library. `sha3_256_prepad32` takes
a 32-byte input with SHA3 padding baked in, which is exactly RinHash's third
stage.

The 64 KiB Argon2d block is a per-thread buffer handed to the library through
`allocate_cbk`, rather than the per-call `malloc`/`free` it does otherwise. It
also guarantees 64-byte alignment on aarch64, where the library's own
`mm_malloc` falls back to plain `malloc`; on x86 the library already requests
64. This is not a throughput optimisation -- measured, it makes no difference at
this `m_cost`. `-DRINHASH_NO_TLS_MEM` selects the library's allocation instead.
