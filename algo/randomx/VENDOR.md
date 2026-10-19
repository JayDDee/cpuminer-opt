# Vendored RandomX core

**Upstream:** https://github.com/tevador/RandomX
**Commit:** `7c761cf007c758056dcb6eb438a32f780f81bdbd` (2026-08-07)
**Vendored:** upstream `src/` copied flat to `algo/randomx/randomx/`, no path rewriting
**License:** BSD-3-Clause (`randomx/LICENSE`), combines freely with cpuminer-opt's
GPLv2-or-later. No file here originates from xmrig.

Upstream is self-contained: it brings its own argon2, blake2b, CPU feature detection and
virtual-memory/W^X layer, so no shim code was needed.

## Dropped from upstream `src/`

- **RISC-V:** `aes_hash_rv64_*`, `jit_compiler_rv64*`, `cpu_rv64.S`, `tests/riscv64_*.s` --
  no RISC-V target in this tree.
- **`assembly_generator_x86.{cpp,hpp}`:** used only by upstream's `randomx-codegen` dev tool;
  nothing in the mining path includes it.
- **`tests/`, `CMakeLists.txt`, `vcxproj/`, `doc/`:** build and dev scaffolding. The test
  vectors were transcribed into `randomx-kat.c`, which cites the upstream line numbers.

Everything else is byte-identical to upstream.

## Do not edit the vendored files

Scoped compiler flags and warning suppressions belong in `Makefile.am`
(`librandomx*_a_CFLAGS`), following the `libcurvehash_secp256k1.a` precedent. Editing the
vendored source turns every future re-sync into a merge.

## Re-sync procedure

```sh
git clone --depth 1 https://github.com/tevador/RandomX
cd RandomX && mkdir build && cd build
cmake -DARCH=native .. && make -j4 && ./randomx-tests   # must pass before you trust it
```

Then copy the file list from `Makefile.am`'s `librandomx_a_SOURCES` and re-run `make check`
here. Re-verify the hex test vectors in `randomx-kat.c` against upstream's `src/tests/tests.cpp`
programmatically rather than by eye -- note upstream's `test_f` key is 32 bytes on the page but
its **key size is 31**, because upstream's helper passes `sizeof(array) - 1`.

## Build notes

- **Do not add `-maes` or a fixed `-march`.** `HAVE_AES` in `intrin_portable.h` degrades to 0
  when `__AES__` / `__ARM_FEATURE_AES` is absent, and there is a portable path for
  `!defined(__SSE2__)` as well, so the core compiles on every ISA tier this tree builds and
  low tiers correctly fall back to soft AES. Inheriting each tier's own flags is what makes a
  build match the CPU it targets.
- **aarch64 needs `-DHAVE_HWCAP`.** `cpu.cpp` gates its ARM AES detection on
  `#if defined(HWCAP_AES)`, which only exists once `<asm/hwcap.h>` has been included, and that
  include sits behind `HAVE_HWCAP`. Without it the hardware-AES path is compiled and then never
  selected. Set from `configure`'s `asm/hwcap.h` check.
- **`randomx_get_flags()` cannot tell "not compiled in" from "CPU lacks it"**, because it ANDs
  the compile-time answer with runtime CPUID. `randomx-buildinfo.cpp` reports the compile-time
  half and must stay inside `librandomx.a` so it sees the library's own flags.
- `librandomx.a` does not link alone: `dataset.cpp` calls
  `randomx_argon2_impl_{ssse3,avx2}()` unconditionally, and the two satellite libraries define
  them (returning NULL when their ISA was not compiled in).
