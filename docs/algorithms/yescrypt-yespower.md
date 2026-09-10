# yescrypt / yespower family

**Coins:** Globalboost-Y, BitZeny, Koto, Yenten, MicroBitcoin, Cryply and many others
**Algorithm names:** `yescrypt`, `yescryptr8`, `yescryptr8g`, `yescryptr16`,
`yescryptr32`, `yespower`, `yespowerr16`, `yespower-b2b`, `power2b`
**Family:** memory-hard, CPU-friendly proof-of-work (password-hashing lineage)

```
./cpuminer -a yespower   -o stratum+tcp://<pool>:<port> -u <wallet> -p x
./cpuminer -a yescryptr16 -o stratum+tcp://<pool>:<port> -u <wallet> -p x
```

---

## Overview

yescrypt and yespower come from the password-hashing world (Solar Designer's
yescrypt KDF). They are **sequential memory-hard** functions: each step depends on
pseudo-random reads from a large memory buffer, which favours CPUs with big, fast
caches and frustrates GPUs and ASICs. yespower is the PoW-focused successor to
yescrypt — simpler, with the client/server split removed.

Both run the same shape per nonce: a PBKDF2-HMAC-SHA256 prehash, a memory-hard core
(`SMix` built on **pwxform** — an input-dependent S-box mixed with Salsa20/8), then a
final PBKDF2 to produce the 32-byte hash compared against the target. The miner does
the SHA-256 prehash of the header's first 64 bytes once, then runs the core per nonce.

The `-b2b` / `power2b` variants replace the internal SHA-256 with **BLAKE2b**.

It uses the standard Bitcoin-style Stratum flow (80-byte header, 32-bit nonce) — there
is no protocol customization; the interesting part is the **parameters**.

## Variants

Each variant fixes a `version`, an `N` (memory cost), an `r` (block size), and a
**personalization string** (`pers`). The personalization is consensus-critical — the
wrong string yields a valid-looking but rejected hash.

| Algo | version | N | r | personalization | Coin |
|---|---|---|---|---|---|
| `yescrypt`    | 0.5 | 2048¹ | 8¹  | from `--param-key` (else none) | Globalboost-Y (BSTY) |
| `yescryptr8`  | 0.5 | 2048 | 8  | `"Client Key"` | BitZeny (ZNY) |
| `yescryptr8g` | 0.5 | 2048 | 8  | **the block header itself** (80 B, or 112 B with sapling) | Koto (KOTO) |
| `yescryptr16` | 0.5 | 4096 | 16 | `"Client Key"` | Eli |
| `yescryptr32` | 0.5 | 4096 | 32 | `"WaviBanana"` | WAVI |
| `yespower`    | 1.0 | 2048¹ | 32¹ | from `--param-key` (else none) | Cryply |
| `yespoweradvc` | 1.0 | 2048 | 32 | `"Let the quest begin"` | AdventureCoin (ADVC) |
| `yespowereqpay`³ | 1.0 | 2048 | 32 | `"The gods had gone away, and the ritual of the religion continued senselessly, uselessly."` | EquityPay (EQPAY) |
| `yespowerltncg` | 1.0 | 2048 | 32 | `"LTNCGYES"` | Crionic (CRNC) |
| `yespowermgpc` | 1.0 | 2048 | 32 | `"Magpies are birds of the Corvidae family."` | MagpieCoin (MGPC) |
| `yespowerr16` | 1.0 | 4096 | 16 | none | Yenten (YTN) |
| `yespowersugar` | 1.0 | 2048 | 32 | `"Satoshi Nakamoto 31/Oct/2008 Proof-of-work is essentially one-CPU-one-vote"` | Sugarchain (SUGAR) |
| `yespowertide` | 1.0 | 2048 | **8** | none | Tidecoin (TDC) |
| `yespowerurx` | 1.0 | 2048 | 32 | `"UraniumX"` | UraniumX (URX) |
| `power2b`     | 1.0 + b2b | 2048 | 32 | `"Now I am become Death, the destroyer of worlds"` | MicroBitcoin (MBC) |
| `yespower-b2b`| 1.0 + b2b | required² | required² | from `--param-key` | generic |

¹ default, overridable from the command line.
² `yespower-b2b` requires `--param-n` and `--param-r`.
³ **not a parameter variant** — see below.

`yespowereqpay` is the one entry in this table that needs more than parameters.
EquityPay is Qtum-derived, so its proof-of-work covers a **181-byte extended
header**, not the usual 80: `hashStateRoot` and `hashUTXORoot` follow the nonce,
then a null `prevoutStake` (a zero hash and `n = 0xffffffff`) and a zero length
byte for the empty block signature. The pool supplies the two roots as a
64-byte tenth Stratum parameter — the same slot `phi2` uses — with each 32-bit
word byte-swapped. It therefore has its own `scanhash` and header builder in
`algo/yespower/yespower-eqpay.c`; the yespower call itself is unchanged, just
given 181 bytes instead of 80.

`yespowertide` is the only variant at `r = 8` with version 1.0 — it inherited
MicroBitcoin's parameters, so it is **not** interchangeable with plain `yespower`
(`r = 32`) despite both having no personalization.

`yespoweradvc` covers AdventureCoin's current parameters. The chain changed
parameters at `nTime > 1553904000`; blocks below that used `0.5 / 4096 / 16 /
"Client Key"`, which is exactly what this miner registers as `yescryptr16`.

The named variants with fixed parameters print their tuple at startup and verify
it against a known-answer vector before mining, so a wrong parameter refuses to
start. Note what that does and does not cover: it proves the tuple is one of the
known ones, not that it is the right one for the coin — the parameters themselves
were read from each coin's daemon source, which is the evidence that they match
consensus.

`yescryptr8g` (Koto) is the odd one out: its personalization is the block header
itself, and its length depends on whether the job is sapling (112 bytes) or not
(80 bytes).

## Parameterized coins

Because `yespower` accepts `N`, `r` and a personalization key on the command line, a
single `-a yespower` (or `-a yespower-b2b`) covers many coins by supplying the right
parameters. For example:

```
# generic forms
--algo yespower     --param-key "<coin personalization>"
--algo yespower     --param-n <N> --param-r <r> --param-key "<key>"
--algo yespower-b2b --param-n <N> --param-r <r> --param-key "<key>"
```

Coins differ only in `(N, r, personalization)`; see the top-level `README.md` for the
exact parameters of specific coins (CPUpower, Sugarchain, and the various
`yespower…` presets).

## Performance

- **SHA-NI prehash.** The PBKDF2-HMAC-SHA256 steps use the CPU SHA extensions where
  present (`SHA256_OPT`).
- **SSE2 / NEON core.** The pwxform/Salsa20 memory-hard core has SSE2 (x86-64) and
  NEON (aarch64) implementations; the BLAKE2b (`-b2b`) variants also use an AVX2 path.
- The memory-hard core is intentionally latency-bound on dependent memory reads — this
  is the algorithm's security property, not an inefficiency.

## Verification

Each implementation matches the reference yescrypt/yespower output; correctness is
confirmed by pool-accepted shares for the specific coin parameters.

A startup self-test runs the whole known-answer vector table on every yespower
registration. Fourteen of the vectors are upstream's own; the rest cover
parameter sets upstream publishes none for, and were produced by agreement
between this tree's two independent implementations (`yespower()` and
`yespower_ref()`), except minotaurx's, which is anchored on a real block.

That table is what catches a mis-built or mis-specialised binary: every variant
shares one source file compiled twice (v0.5 and v1.0) across four ISA paths, and
any one build exercises a single path.

## Possible optimizations (preview)

- **Wider pwxform** — AVX2/AVX-512 implementations of the pwxform S-box mixing for the
  larger-`r` variants.
- **SHA-NI / BLAKE2b coverage** — ensure the prehash and the `-b2b` core take the
  hardware-accelerated path on every supported CPU.
- **Cache-aware scheduling** — size the per-thread memory regions to the CPU's cache
  hierarchy so independent per-thread instances don't thrash shared cache.
