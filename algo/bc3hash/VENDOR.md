# bc3hash: provenance

Source: Bitcoin III Core, <https://gitlab.com/bitcoiniii/bitcoiniii-core>,
commit `ac3dbe8b47c6b822531ed7f7dfc2fa4e9a295b2a` (2026-10-14), `src/crypto/bc3/`.
MIT license, same as the rest of that repository.

## File mapping

| Here | Upstream | Relation |
|---|---|---|
| `bc3hash-uint.hpp` | `uint.hpp` | Same arithmetic. `constexpr` dropped in places; the 512-bit moduli (`M512`, `F512`) removed |
| `bc3hash-constants.hpp` | `constants.hpp` | Same values, same order. `E512`, `g512`, `BC3FOLD_CONST` removed |
| `bc3hash-core.cpp` | `mix.cpp` + `hash.cpp` | Derived; see below |
| `bc3hash-hashes.hpp` | `standard_hashes.hpp` | Same interface |
| `bc3hash-hashes-framework.cpp` | `standard_hashes.cpp` | Rewritten on this tree's `sph_*` hashes |

## What was removed

- **BC3Fold** (`Fold`, `bc3fold`, `generator_table`, the streaming `Mix`/`Hash` classes):
  BC3Mix only folds inputs that are not exactly 64 bytes. bc3hash always feeds it the
  64-byte SHA3-512 digest, so the fold never runs on the PoW path.
- `configure()` / `Mode`: replaced by the runtime window below.

## What was changed

- The curve table window is set at runtime (`-a bc3hash:W`, default 16) instead of
  through upstream's compact/fast mode (windows 10/16). Digests are identical at every window.
- The tables are allocated once and never freed. The miner calls `exit()` while
  hashing threads are still running, and destroying them then is a use-after-free.
- The curve tables and the scalar multiplications run on `bc3hash-ec.c` (see below)
  instead of `secp256k1_ec_pubkey_combine`/`_serialize`. `mix512` hands it a round's
  four multiplications together (`curve_mult4`). Same points, so same digests.
- The 64-bit message schedule in `mix512` runs over a rolling window instead of
  indexing the array it writes. Upstream's form is miscompiled by gcc 13 at `-O3`
  unless `-fno-strict-aliasing` is set (the loop vectorizer breaks its distance-1
  recurrence). Same values, checked against the coin's reference.
- `mix512` is split into `mix_front` (64/128-bit rounds) and `mix_lanes<N>`, which runs N
  nonces in lockstep so their curve mults and final-step inversions share one inversion
  (`curve_mult<M>`, `inverse256_lanes<N>`). Each nonce's arithmetic is unchanged; the miner
  hashes `BC3HASH_LANES` (16) nonces per call.
- Built with AVX-512 IFMA, `bc3hash-ec.c` also adds up eight curve sums at once (`sum8_ifma`:
  the same Jacobian + affine additions as `gej_add_ge_var`, in 5x52-bit limbs), with libsecp
  redoing any sum whose result has Z = 0 (mod p). Same points, so same digests.
- Built with AVX-512 IFMA (`__AVX512IFMA__`), the lockstep path runs `exp256` for 16 values at
  once in 5x52-bit limbs (`bc3hash-ifma.hpp`); the single-nonce path and every other target keep
  the scalar `FixedExponent`. Same canonical results; `-DBC3HASH_NO_IFMA` turns it off.
- On x86-64 with BMI2+ADX, `Mod<4,C>::mul` is one inline-asm block (`mulmod_asm`: `mulx`
  with `adcx`/`adox` carry chains, all in registers), or the `mulx`/`adc` intrinsics at `-O0` or
  with `-DBC3HASH_NO_ASM_MUL`. `FixedPower` keeps the portable row-wise product (`mul_rows`),
  which is faster there.
  Same integer product and reduction, so same values.
- The group order is parsed once, not per call. `inverse_odd64(36113)` is folded to a constant.
- The structured bindings in `mix512` are spelled out as `std::pair` members.
- An `extern "C"` API (`bc3_hash_cxx`, `bc3_hash_init_cxx`, `bc3_hash_*_window`,
  `bc3_hash_table_bytes`) for the C gate.

## libsecp256k1 (`secp256k1/`)

`bc3hash-ec.c` includes the field and group internals of libsecp256k1 commit
`57315a6985` (master shortly after v0.7.1), the subtree the coin itself ships in
`src/secp256k1` at the commit above. MIT license, `secp256k1/COPYING`. Only the 15
`src/` headers that TU reaches and `include/secp256k1.h` are kept, unmodified; list
them with `gcc -MM` on `bc3hash-ec.c`. No `.c` file, no public API, no precomputed
tables. Everything included is `static`, so it cannot clash with curvehash's older
copy in the same binary (check: `nm libbc3hash.a` shows no `secp256k1_` symbol).
Re-sync by copying the same files from a newer subtree and re-running the checks below.

The libsecp256k1 vendored for curvehash (2015, public API) stays linked as the startup
oracle: `ec_self_test()` in `bc3hash-core.cpp` recomputes k*P with its
`ec_pubkey_tweak_mul` and requires the kernel to match on every table.

## Checking a re-sync

Don't compare by eye. Parse both sides:

- every `::hex("...")` constant in `bc3hash-constants.hpp` must appear in upstream's
  `constants.hpp`, in the same order;
- `mix512`, `inverse256` and its helpers in `bc3hash-core.cpp` must match `mix.cpp`
  after whitespace normalisation, except for the changes listed above;
- the functions in `bc3hash-uint.hpp` must match `uint.hpp` modulo `constexpr`/`inline`.

Then the startup self-tests (the EC oracle above, and `bc3hash-kat.h`: two mainnet
blocks and two of upstream's `doc/bc3/vectors/header-vectors.json` entries) must pass
at windows 10 and 16.
