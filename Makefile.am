
if HAVE_APPLE
# MacOS uses Homebrew to install needed packages but they aren't linked for
# the jansson test in configure. Ignore the failed test & link them now,
# different path for different CPU arch.

if ARCH_ARM64
  EXTRA_INCLUDES = -I/opt/homebrew/include
  EXTRA_LIBS     = -L/opt/homebrew/lib
else
  EXTRA_INCLUDES = -I/usr/local/include
  EXTRA_LIBS     = -L/usr/local/lib
endif

else

if WANT_JANSSON
# Can't find jansson libraries, compile the included source code.
  EXTRA_INCLUDES = -I$(top_srcdir)/compat/jansson
  EXTRA_LIBS     = -L$(top_srcdir)/compat/jansson
else
  EXTRA_INCLUDES =
  EXTRA_LIBS     =
endif

endif

EXTRA_DIST = example-cfg.json nomacro.pl

SUBDIRS = compat

ALL_INCLUDES = @PTHREAD_FLAGS@ -fno-strict-aliasing $(EXTRA_INCLUDES) -I.

bin_PROGRAMS = cpuminer

dist_man_MANS = cpuminer.1

# curvehash's PoW *is* libsecp256k1, vendored under algo/curvehash/secp256k1 and
# compiled as a single TU. It lives in its own convenience library for two
# reasons, both scoping:
#   - the library's internal #include "include/secp256k1.h" only resolves from
#     the library root, and that -I has no business on every other TU's command
#     line;
#   - a 2015-vintage C89 library trips -Wall on current compilers (36
#     nonnull-compare from its own ARG_CHECK macros, 4 unused-function inherent
#     to a unity build). Those are suppressed here, per-object, so the rest of
#     the tree keeps them. Do NOT suppress them tree-wide and do NOT edit the
#     vendored source -- that is an upstream-sync trap.
# -Wno-unknown-warning-option comes first because -Wnonnull-compare is GCC-only;
# clang needs it to stay quiet, and GCC ignores it. Verified 0 warnings on both.
# curvehash-kernel.c is the extracted k*G subset -- the file mining actually
# runs. It includes the same vendored headers, so it needs the same scoped -I
# and the same -Wno-, and therefore belongs in this library rather than in
# cpuminer_SOURCES.
noinst_LIBRARIES = libcurvehash_secp256k1.a
libcurvehash_secp256k1_a_SOURCES = algo/curvehash/secp256k1_unity.c \
  algo/curvehash/curvehash-kernel.c
libcurvehash_secp256k1_a_CPPFLAGS = $(ALL_INCLUDES) \
  -I$(top_srcdir)/algo/curvehash/secp256k1
libcurvehash_secp256k1_a_CFLAGS = $(disable_flags) \
  -Wno-unknown-warning-option -Wno-nonnull-compare -Wno-unused-function

# RandomX: the tevador BSD-3 core, vendored under algo/randomx/randomx.
# Provenance, dropped files, re-sync procedure and build notes: VENDOR.md there.
# Its own convenience library, for three scoping reasons:
#   - it is C++ with flat internal includes, and brings its own argon2 and
#     blake2b whose names would otherwise sit on every other TU's include path
#     next to algo/argon2d's;
#   - argon2_ssse3.c and argon2_avx2.c each need their own -m flag, and automake
#     scopes flags per library, not per file -- hence the two satellites below;
#   - upstream stays unedited, so its warnings are silenced per-object.
# Deliberately NO -maes/-march: the core falls back to soft AES at runtime when
# the ISA is absent, so inheriting each tier's own CFLAGS is what makes a tier
# build match the CPU it targets. randomx-kat prints what was selected.
RANDOMX_INCLUDES = $(ALL_INCLUDES) -I$(top_srcdir)/algo/randomx
# unused-variable/-function in the vendored argon2 and per-ISA stubs. Silenced
# per-object so the rest of the tree keeps them and upstream stays unedited.
# -Wno-unknown-warning-option first for clang; GCC ignores it.
RANDOMX_QUIET = -Wno-unknown-warning-option -Wno-unused-function \
  -Wno-unused-variable

if HAVE_RANDOMX
noinst_LIBRARIES += librandomx.a

# Shared between the stock core and every per-variant copy. Must be a plain
# variable holding literal filenames: automake expands one of these into an
# object list, but it will NOT expand a reference to another *_SOURCES -- doing
# that yields a library with ZERO objects and no warning.
RANDOMX_CORE_SRC = \
  algo/randomx/randomx-buildinfo.cpp \
  algo/randomx/randomx/aes_hash.cpp \
  algo/randomx/randomx/allocator.cpp \
  algo/randomx/randomx/blake2_generator.cpp \
  algo/randomx/randomx/bytecode_machine.cpp \
  algo/randomx/randomx/cpu.cpp \
  algo/randomx/randomx/dataset.cpp \
  algo/randomx/randomx/instruction.cpp \
  algo/randomx/randomx/instructions_portable.cpp \
  algo/randomx/randomx/randomx.cpp \
  algo/randomx/randomx/soft_aes.cpp \
  algo/randomx/randomx/superscalar.cpp \
  algo/randomx/randomx/virtual_machine.cpp \
  algo/randomx/randomx/vm_compiled.cpp \
  algo/randomx/randomx/vm_compiled_light.cpp \
  algo/randomx/randomx/vm_interpreted.cpp \
  algo/randomx/randomx/vm_interpreted_light.cpp \
  algo/randomx/randomx/argon2_core.c \
  algo/randomx/randomx/argon2_ref.c \
  algo/randomx/randomx/reciprocal.c \
  algo/randomx/randomx/virtual_memory.c \
  algo/randomx/randomx/blake2/blake2b.c

RANDOMX_CORE_CPPFLAGS = $(RANDOMX_INCLUDES)
RANDOMX_CORE_CFLAGS   = $(disable_flags) $(RANDOMX_QUIET)
RANDOMX_CORE_CXXFLAGS = $(disable_flags) $(RANDOMX_QUIET)

librandomx_a_SOURCES   = $(RANDOMX_CORE_SRC)
librandomx_a_CPPFLAGS  = $(RANDOMX_CORE_CPPFLAGS)
librandomx_a_CFLAGS    = $(RANDOMX_CORE_CFLAGS)
librandomx_a_CXXFLAGS  = $(RANDOMX_CORE_CXXFLAGS)
librandomx_a_CCASFLAGS = $(RANDOMX_CORE_CPPFLAGS)

# librandomx.a alone is not linkable: the argon2 satellites define
# randomx_argon2_impl_{ssse3,avx2}(), which dataset.cpp calls unconditionally
# (returning NULL when their ISA was not compiled in). Link all three.
RANDOMX_LIBS = librandomx.a

if HAVE_RANDOMX_VARIANTS
# ------------------------------------------------ second core: rx/wow
#
# rx/wow moves scratchpad sizes, program iterations/count and 8 instruction
# frequencies. Those are constexpr in the core's common.hpp and one of them is
# an `and` immediate inside jit_compiler_x86_static.S, so the variant cannot
# share rx/0's compiled core -- it gets its own, built from the same sources
# with config/wow.h injected.
#
# Both copies define the randomx_* C API and the entire randomx:: C++
# namespace, so the variant copy is run through prefix-syms.sh, which renames
# every symbol it DEFINES to rxwow_*. randomx-core.c then binds the prefixed
# names into a function table. Anything that talks to a core goes through that
# table; randomx-kat.c deliberately does not, because its vectors are rx/0's.
#
# _raw archives are the compiler's output; the prefixed ones are what link.
noinst_LIBRARIES += librandomx_wow_raw.a
librandomx_wow_raw_a_SOURCES   = $(RANDOMX_CORE_SRC)
librandomx_wow_raw_a_CPPFLAGS  = $(RANDOMX_CORE_CPPFLAGS) $(RANDOMX_WOW_CONFIG)
librandomx_wow_raw_a_CFLAGS    = $(RANDOMX_CORE_CFLAGS)
librandomx_wow_raw_a_CXXFLAGS  = $(RANDOMX_CORE_CXXFLAGS)
librandomx_wow_raw_a_CCASFLAGS = $(RANDOMX_CORE_CPPFLAGS) $(RANDOMX_WOW_CONFIG)

RANDOMX_WOW_CONFIG = -include $(top_srcdir)/algo/randomx/config/wow.h
RANDOMX_PREFIX_SYMS = $(top_srcdir)/algo/randomx/prefix-syms.sh
RANDOMX_VARIANT_DEFINES = -DRANDOMX_HAVE_WOW_CORE

librandomx_wow.a: librandomx_wow_raw.a $(RANDOMX_PREFIX_SYMS)
	$(AM_V_GEN)$(SHELL) $(RANDOMX_PREFIX_SYMS) $< $@ rxwow_ "$(NM)" "$(OBJCOPY)"

RANDOMX_LIBS += librandomx_wow.a

# ------------------------------------------------ third core: rx/graft
# Same mechanism as rx/wow. Graft moves two instruction frequencies and the
# program size, all constexpr in common.hpp, so it too needs its own core.
noinst_LIBRARIES += librandomx_graft_raw.a
librandomx_graft_raw_a_SOURCES   = $(RANDOMX_CORE_SRC)
librandomx_graft_raw_a_CPPFLAGS  = $(RANDOMX_CORE_CPPFLAGS) $(RANDOMX_GRAFT_CONFIG)
librandomx_graft_raw_a_CFLAGS    = $(RANDOMX_CORE_CFLAGS)
librandomx_graft_raw_a_CXXFLAGS  = $(RANDOMX_CORE_CXXFLAGS)
librandomx_graft_raw_a_CCASFLAGS = $(RANDOMX_CORE_CPPFLAGS) $(RANDOMX_GRAFT_CONFIG)

RANDOMX_GRAFT_CONFIG = -include $(top_srcdir)/algo/randomx/config/graft.h
RANDOMX_ARQ_CONFIG   = -include $(top_srcdir)/algo/randomx/config/arq.h

librandomx_graft.a: librandomx_graft_raw.a $(RANDOMX_PREFIX_SYMS)
	$(AM_V_GEN)$(SHELL) $(RANDOMX_PREFIX_SYMS) $< $@ rxgrft_ "$(NM)" "$(OBJCOPY)"

RANDOMX_LIBS += librandomx_graft.a
RANDOMX_VARIANT_DEFINES += -DRANDOMX_HAVE_GRAFT_CORE

# ------------------------------------------------ fourth core: rx/arq
# ArQmA moves the scratchpad sizes and the program count/iterations.
noinst_LIBRARIES += librandomx_arq_raw.a
librandomx_arq_raw_a_SOURCES   = $(RANDOMX_CORE_SRC)
librandomx_arq_raw_a_CPPFLAGS  = $(RANDOMX_CORE_CPPFLAGS) $(RANDOMX_ARQ_CONFIG)
librandomx_arq_raw_a_CFLAGS    = $(RANDOMX_CORE_CFLAGS)
librandomx_arq_raw_a_CXXFLAGS  = $(RANDOMX_CORE_CXXFLAGS)
librandomx_arq_raw_a_CCASFLAGS = $(RANDOMX_CORE_CPPFLAGS) $(RANDOMX_ARQ_CONFIG)

librandomx_arq.a: librandomx_arq_raw.a $(RANDOMX_PREFIX_SYMS)
	$(AM_V_GEN)$(SHELL) $(RANDOMX_PREFIX_SYMS) $< $@ rxarq_ "$(NM)" "$(OBJCOPY)"

RANDOMX_LIBS += librandomx_arq.a
RANDOMX_VARIANT_DEFINES += -DRANDOMX_HAVE_ARQ_CORE

# ------------------------------------------- fifth core: panthera (Scala)
# Panthera is a tier-2 variant PLUS a seed hook: it post-processes the initial
# seed with yespower and KangarooTwelve. config/panthera.h supplies both the
# constants and RANDOMX_SEED_HOOK; the hook body lives in panthera-seed.c,
# outside the core, so this archive keeps an unprefixed reference to it (the
# same arrangement as the shared argon2 satellites).
noinst_LIBRARIES += librandomx_panthera_raw.a
librandomx_panthera_raw_a_SOURCES   = $(RANDOMX_CORE_SRC)
librandomx_panthera_raw_a_CPPFLAGS  = $(RANDOMX_CORE_CPPFLAGS) $(RANDOMX_PAN_CONFIG)
librandomx_panthera_raw_a_CFLAGS    = $(RANDOMX_CORE_CFLAGS)
librandomx_panthera_raw_a_CXXFLAGS  = $(RANDOMX_CORE_CXXFLAGS)
librandomx_panthera_raw_a_CCASFLAGS = $(RANDOMX_CORE_CPPFLAGS) $(RANDOMX_PAN_CONFIG)

RANDOMX_PAN_CONFIG   = -include $(top_srcdir)/algo/randomx/config/panthera.h

librandomx_panthera.a: librandomx_panthera_raw.a $(RANDOMX_PREFIX_SYMS)
	$(AM_V_GEN)$(SHELL) $(RANDOMX_PREFIX_SYMS) $< $@ rxpan_ "$(NM)" "$(OBJCOPY)"

RANDOMX_LIBS += librandomx_panthera.a
RANDOMX_VARIANT_DEFINES += -DRANDOMX_HAVE_PANTHERA_CORE
endif
# ^ HAVE_RANDOMX_VARIANTS
# NB: CLEANFILES is assigned with '=' further down, so the prefixed archives are
# added there, not here -- a '+=' at this point would be silently discarded.

if ARCH_x86_64
RANDOMX_CORE_SRC += \
  algo/randomx/randomx/jit_compiler_x86.cpp \
  algo/randomx/randomx/jit_compiler_x86_static.S
noinst_LIBRARIES += librandomx_ssse3.a librandomx_avx2.a
RANDOMX_LIBS += librandomx_ssse3.a librandomx_avx2.a
librandomx_ssse3_a_SOURCES = algo/randomx/randomx/argon2_ssse3.c
librandomx_ssse3_a_CPPFLAGS = $(RANDOMX_INCLUDES)
librandomx_ssse3_a_CFLAGS = $(disable_flags) $(RANDOMX_QUIET) -mssse3
librandomx_avx2_a_SOURCES = algo/randomx/randomx/argon2_avx2.c
librandomx_avx2_a_CPPFLAGS = $(RANDOMX_INCLUDES)
librandomx_avx2_a_CFLAGS = $(disable_flags) $(RANDOMX_QUIET) -mavx2
else
# Off x86 both compile to a stub returning NULL, so they need no flags and no
# separate library -- but they must still be compiled or the link fails.
RANDOMX_CORE_SRC += \
  algo/randomx/randomx/argon2_ssse3.c \
  algo/randomx/randomx/argon2_avx2.c
if ARCH_ARM64
RANDOMX_CORE_SRC += \
  algo/randomx/randomx/jit_compiler_a64.cpp \
  algo/randomx/randomx/jit_compiler_a64_static.S
if HAVE_ASM_HWCAP
# Without this, cpu.cpp's aarch64 branch cannot see HWCAP_AES, so the
# hardware-AES path is compiled and then never selected. randomx-kat prints the
# compile-time and runtime answers side by side.
RANDOMX_CORE_CPPFLAGS += -DHAVE_HWCAP
endif
endif
endif

# Known-answer tests for the vendored core. `make check` runs light mode;
# `./randomx-kat --full` adds the fast-mode path, the only thing that exercises
# randomx_init_dataset(). --bench and --sweep are measurement modes.
#
# randomx-kat.c holds the vectors and is also compiled into cpuminer so the algo
# gate can run a quick subset at startup; only main() lives in -main.c, so the
# vectors are never compiled twice with different macros.
#
# dummy.cpp forces the C++ linker, as in cpuminer_SOURCES.
check_PROGRAMS = randomx-kat
TESTS = randomx-kat
randomx_kat_SOURCES = algo/randomx/randomx-kat-main.c \
  algo/randomx/randomx-kat.c dummy.cpp
randomx_kat_CPPFLAGS = $(RANDOMX_INCLUDES)
randomx_kat_CFLAGS = $(disable_flags)
randomx_kat_LDADD = $(RANDOMX_LIBS) $(EXTRA_LIBS) @PTHREAD_LIBS@
endif
# ^ HAVE_RANDOMX

cpuminer_SOURCES = \
  dummy.cpp \
  cpu-miner.c \
  util.c \
  api.c \
  api_model.c \
  api_http.c \
  api_routes.c \
  api_metrics.c \
  api_control.c \
  sysinfos.c \
  algo-gate-api.c\
  malloc-huge.c \
  simd-utils/simd-constants.c \
  algo/argon2d/argon2d-gate.c \
  algo/argon2d/blake2/blake2b.c \
  algo/argon2d/argon2d/argon2.c \
  algo/argon2d/argon2d/core.c \
  algo/argon2d/argon2d/opt.c \
  algo/argon2d/argon2d/argon2d_thread.c \
  algo/argon2d/argon2d/encoding.c \
  algo/balloon/balloon.c \
  algo/balloon/balloon-aes128.c \
  algo/balloon/balloon-gate.c \
  algo/blake/sph_blake.c \
  algo/blake/blake256-hash.c \
  algo/blake/blake512-hash.c \
  algo/blake/blake-gate.c \
  algo/blake/blake.c \
  algo/blake/blake-4way.c \
  algo/blake/sph_blake2b.c \
  algo/blake/sph-blake2s.c \
  algo/blake/blake2s-hash.c \
  algo/blake/blake2s.c \
  algo/blake/blake2b-hash.c \
  algo/blake/blake2b.c \
  algo/blake/blakecoin-gate.c \
  algo/blake/mod_blakecoin.c \
  algo/blake/blakecoin.c \
  algo/blake/blakecoin-4way.c \
  algo/blake/pentablake-gate.c \
  algo/blake/pentablake-4way.c \
  algo/blake/pentablake.c \
  algo/bmw/sph_bmw.c \
  algo/bmw/bmw256-hash-4way.c \
  algo/bmw/bmw512-hash-4way.c \
  algo/bmw/bmw256.c \
  algo/bmw/bmw512-gate.c \
  algo/bmw/bmw512.c \
  algo/bmw/bmw512-4way.c \
  algo/cubehash/cubehash_sse2.c\
  algo/cubehash/cube-hash-2way.c \
  algo/cubehash/sph_cubehash.c \
  algo/curvehash/curvehash-gate.c \
  algo/equihash/equihash.c \
  algo/equihash/equihash-ref.c \
  algo/equihash/equihash-simd.c \
  algo/equihash/equihash-gate.c \
  algo/echo/sph_echo.c \
  algo/echo/echo-hash-4way.c \
  algo/echo/aes_ni/hash.c\
  algo/gost/sph_gost.c \
  algo/flex/flex-gate.c \
  algo/flex/cryptonote/cryptonight_dark.c \
  algo/flex/cryptonote/cryptonight_dark_lite.c \
  algo/flex/cryptonote/cryptonight_fast.c \
  algo/flex/cryptonote/cryptonight_lite.c \
  algo/flex/cryptonote/cryptonight_turtle.c \
  algo/flex/cryptonote/cryptonight_turtle_lite.c \
  algo/gr/gr-gate.c \
  algo/gr/cryptonight.c \
  algo/gr/cryptonote/crypto/hash.c \
  algo/gr/cryptonote/crypto/oaes_lib.c \
  algo/gr/cryptonote/crypto/aesb.c \
  algo/gr/cryptonote/crypto/c_keccak.c \
  algo/gr/cryptonote/crypto/c_blake256.c \
  algo/gr/cryptonote/crypto/c_groestl.c \
  algo/gr/cryptonote/crypto/c_jh.c \
  algo/gr/cryptonote/crypto/c_skein.c \
  algo/mike/mike-gate.c \
  algo/groestl/groestl-gate.c \
  algo/groestl/groestl512-hash-4way.c \
  algo/groestl/groestl256-hash-4way.c \
  algo/groestl/sph_groestl.c \
  algo/groestl/groestl.c \
  algo/groestl/groestl-4way.c \
  algo/groestl/myrgr-gate.c \
  algo/groestl/myrgr-4way.c \
  algo/groestl/myr-groestl.c \
  algo/groestl/aes_ni/hash-groestl.c \
  algo/groestl/aes_ni/hash-groestl256.c \
  algo/fugue/sph_fugue.c \
  algo/fugue/fugue-aesni.c \
  algo/hamsi/sph_hamsi.c \
  algo/hamsi/hamsi-hash-4way.c \
  algo/haval/haval.c \
  algo/haval/haval-hash-4way.c \
  algo/jh/sph_jh.c \
  algo/jh/jh-hash-4way.c \
  algo/jh/jha-gate.c \
  algo/jh/jha-4way.c \
  algo/jh/jha.c \
  algo/keccak/sph_keccak.c \
  algo/keccak/keccak.c\
  algo/keccak/keccak-hash-4way.c \
  algo/keccak/keccak-4way.c\
  algo/keccak/keccak-gate.c \
  algo/keccak/sha3d-4way.c \
  algo/keccak/sha3d.c \
  algo/keccak/sha3t-4way.c \
  algo/keccak/sha3t.c \
  algo/lanehash/lane.c \
  algo/luffa/luffa_for_sse2.c \
  algo/luffa/luffa-hash-2way.c \
  algo/luffa/sph_luffa.c \
  algo/lyra2/lyra2.c \
  algo/lyra2/sponge.c \
  algo/lyra2/sponge-2way.c \
  algo/lyra2/lyra2-hash-2way.c \
  algo/lyra2/lyra2-gate.c \
  algo/lyra2/lyra2rev2.c \
  algo/lyra2/lyra2rev2-4way.c \
  algo/lyra2/lyra2rev3.c \
  algo/lyra2/lyra2rev3-4way.c \
  algo/lyra2/lyra2re.c \
  algo/lyra2/lyra2z-4way.c \
  algo/lyra2/lyra2z330.c \
  algo/lyra2/lyra2h.c \
  algo/lyra2/lyra2h-4way.c \
  algo/lyra2/allium-4way.c \
  algo/lyra2/phi2-4way.c \
  algo/lyra2/phi2.c \
  algo/m7m/m7m.c \
  algo/nist5/nist5-gate.c \
  algo/nist5/nist5-4way.c \
  algo/nist5/nist5.c \
  algo/nist5/zr5.c \
  algo/odo/odocrypt.c \
  algo/odo/odo-gate.c \
  algo/panama/panama-hash-4way.c \
  algo/panama/sph_panama.c \
  algo/quark/quark-gate.c \
  algo/quark/quark.c \
  algo/quark/quark-4way.c \
  algo/quark/anime-gate.c \
  algo/quark/anime.c \
  algo/quark/anime-4way.c \
  algo/quark/hmq1725-gate.c \
  algo/quark/hmq1725-4way.c \
  algo/quark/hmq1725.c \
  algo/qubit/qubit-gate.c \
  algo/qubit/qubit.c \
  algo/qubit/qubit-2way.c \
  algo/qubit/deep-gate.c \
  algo/qubit/deep-2way.c \
  algo/qubit/deep.c \
  algo/ripemd/sph_ripemd.c \
  algo/ripemd/ripemd-hash-4way.c \
  algo/ripemd/lbry-gate.c \
  algo/ripemd/lbry.c \
  algo/ripemd/lbry-4way.c \
  algo/scrypt/scrypt.c \
  algo/scrypt/scrypt-core-4way.c \
  algo/scrypt/neoscrypt.c \
  algo/sha/sha1.c \
  algo/sha/sha1-hash.c \
  algo/sha/sha256-hash.c \
  algo/sha/sph_sha2.c \
  algo/sha/sph_sha2big.c \
  algo/sha/sha256-hash-4way.c \
  algo/sha/sha512-hash-4way.c \
  algo/sha/hmac-sha256-hash.c \
  algo/sha/hmac-sha256-hash-4way.c \
  algo/sha/sha256d.c \
  algo/sha/sha256d-4way.c \
  algo/sha/sha256t-gate.c \
  algo/sha/sha256t-4way.c \
  algo/sha/sha256q-4way.c \
  algo/sha/sha256q.c \
  algo/sha/sha512256d-4way.c \
  algo/sha/sha256dv.c \
  algo/sha/sha256dt.c \
  algo/sha/sha256csm.c \
  algo/shabal/sph_shabal.c \
  algo/shabal/shabal-hash-4way.c \
  algo/shavite/sph_shavite.c \
  algo/shavite/sph-shavite-aesni.c \
  algo/shavite/shavite-hash-2way.c \
  algo/shavite/shavite-hash-4way.c \
  algo/simd/sph_simd.c \
  algo/simd/simd-hash-2way.c \
  algo/skein/sph_skein.c \
  algo/skein/skein-hash-4way.c \
  algo/skein/skein.c \
  algo/skein/skein-4way.c \
  algo/skein/skein-gate.c \
  algo/skein/skein2.c \
  algo/skein/skein2-4way.c \
  algo/sm3/sm3.c \
  algo/sm3/sm3-hash-4way.c \
  algo/swifftx/swifftx.c \
  algo/tiger/sph_tiger.c \
  algo/verthash/verthash-gate.c \
  algo/verthash/Verthash.c \
  algo/verthash/fopen_utf8.c \
  algo/verthash/tiny_sha3/sha3.c \
  algo/verthash/tiny_sha3/sha3-4way.c \
  algo/verus/haraka.c \
  algo/verus/haraka_portable.c \
  algo/verus/verus_clhash.c \
  algo/verus/verus_clhash_2way.c \
  algo/verus/verus-gate.c \
  algo/whirlpool/sph_whirlpool.c \
  algo/whirlpool/whirlpool-gate.c \
  algo/whirlpool/whirlpool.c \
  algo/whirlpool/whirlpoolx.c \
  algo/whirlpool/whirlpoolx2.c \
  algo/x11/x11-gate.c \
  algo/x11/x11.c \
  algo/x11/x11-4way.c \
  algo/x11/x11gost-gate.c \
  algo/x11/x11gost.c \
  algo/x11/x11gost-4way.c \
  algo/x11/c11-gate.c \
  algo/x11/c11.c \
  algo/x11/c11-4way.c \
  algo/x11/tribus-gate.c \
  algo/x11/tribus.c \
  algo/x11/tribus-4way.c \
  algo/x11/timetravel-gate.c \
  algo/x11/timetravel.c \
  algo/x11/timetravel-4way.c \
  algo/x11/timetravel10-gate.c \
  algo/x11/timetravel10.c \
  algo/x11/timetravel10-4way.c \
  algo/fugue/fugue-hash-4way.c \
  algo/rinhash/rinhash.c \
  algo/x11/megabtx-gate.c \
  algo/x11/megabtx.c \
  algo/x11/megabtx-4way.c \
  algo/x11/x11evo.c \
  algo/x11/x11evo-4way.c \
  algo/x11/x11evo-gate.c \
  algo/x12/x12-gate.c \
  algo/x12/x12.c \
  algo/x12/x12-4way.c \
  algo/x13/x13-gate.c \
  algo/x13/x13.c \
  algo/x13/x13-4way.c \
  algo/x13/x13sm3-gate.c \
  algo/x13/x13sm3.c \
  algo/x13/x13sm3-4way.c \
  algo/x13/phi1612-gate.c \
  algo/x13/phi1612.c \
  algo/x13/phi1612-4way.c \
  algo/x13/skunk-gate.c \
  algo/x13/skunk-4way.c \
  algo/x13/skunk.c \
  algo/x13/x13bcd-4way.c \
  algo/x13/x13bcd.c \
  algo/x14/x14-gate.c \
  algo/x14/x14.c \
  algo/x14/x14-4way.c \
  algo/x14/veltor-gate.c \
  algo/x14/veltor.c \
  algo/x14/veltor-4way.c \
  algo/x14/polytimos-gate.c \
  algo/x14/polytimos.c \
  algo/x14/polytimos-4way.c \
  algo/x14/axiom.c \
  algo/x15/x15-gate.c \
  algo/x15/x15.c \
  algo/x15/x15-4way.c \
  algo/x16/x16r-gate.c \
  algo/x16/x16r.c \
  algo/x16/x16r-4way.c \
  algo/x16/x16rv2.c \
  algo/x16/soterg.c \
  algo/x16/soterg-4way.c \
  algo/x16/x16rv2-4way.c \
  algo/x16/x16rt.c \
  algo/x16/x16rt-4way.c \
  algo/x16/hex.c \
  algo/x16/x20r.c \
  algo/x16/x21s-4way.c \
  algo/x16/x21s.c \
  algo/x16/minotaur.c \
  algo/x17/x17-gate.c \
  algo/x17/x17.c \
  algo/x17/x17-4way.c \
  algo/x17/xevan-gate.c \
  algo/x17/xevan.c \
  algo/x17/xevan-4way.c \
  algo/x17/sonoa-gate.c \
  algo/x17/sonoa-4way.c \
  algo/x17/sonoa.c \
  algo/x17/skydoge.c \
  algo/x17/skydoge-4way.c \
  algo/x17/skydoge-8way.c \
  algo/blake3/blake3.c \
  algo/blake3/blake3_dispatch.c \
  algo/blake3/blake3_portable.c \
  algo/heavyhash/heavyhash.c \
  algo/hoohash/hoohash.c \
  algo/x22/x22i-4way.c \
  algo/x22/x22i.c \
  algo/x22/x22i-gate.c \
  algo/x22/x25x.c \
  algo/x22/x25x-4way.c \
  algo/yespower/yespower-gate.c \
  algo/yespower/yespower-eqpay.c \
  algo/yespower/yespower-blake2b.c \
  algo/yespower/crypto/hmac-blake2b.c \
  algo/yespower/yescrypt-r8g.c \
  algo/yespower/yespower-opt.c \
  algo/yespower/yespower-ref.c \
  algo/yespower/yespower-blake2b-ref.c

if HAVE_WINDOWS
   cpuminer_SOURCES += compat/winansi.c
endif

if USE_ASM
   disable_flags =
   cpuminer_SOURCES += asm/neoscrypt_asm.S
else
   disable_flags = -DNOASM
endif

cpuminer_LDFLAGS = @LDFLAGS@
# RandomX sources, or a stub satisfying the seven entry points cpu-miner.c and
# util.c reference, so neither file needs an #ifdef. rx_algo_is_randomx()
# answers false in the stub, so those call sites take the bitcoin-stratum path
# and the remaining stubs are never reached.
if HAVE_RANDOMX
cpuminer_SOURCES += \
  algo/randomx/randomx-gate.c \
  algo/randomx/randomx-stratum.c \
  algo/randomx/randomx-vm.c \
  algo/randomx/randomx-variant.c \
  algo/randomx/randomx-core.c \
  algo/randomx/panthera-seed.c \
  algo/k12/k12-gate.c \n  algo/k12/KangarooTwelve.c \
  algo/k12/KeccakP-1600-reference.c \
  algo/k12/KeccakSpongeWidth1600.c \
  algo/randomx/randomx-kat.c
else
cpuminer_SOURCES += algo/randomx/randomx-stub.c
endif

cpuminer_LDADD	= libcurvehash_secp256k1.a $(RANDOMX_LIBS) $(EXTRA_LIBS) @LIBCURL@ -ljansson @PTHREAD_LIBS@ @WS2_LIBS@ -lgmp build-stamp.$(OBJEXT)

# Carries the date for the "SW built on" banner. Depends on the objects, so it
# is regenerated exactly when a relink is due: `make` with nothing to do stays a
# no-op, and the date printed is when the binary was actually linked. __DATE__
# in cpu-miner.c cannot do this -- make does not recompile that file when some
# other one changes.
EXTRA_cpuminer_DEPENDENCIES = build-stamp.$(OBJEXT)
CLEANFILES = build-stamp.c build-stamp.$(OBJEXT) \
  librandomx_wow.a librandomx_wow.a.syms \
  librandomx_graft.a librandomx_graft.a.syms \
  librandomx_arq.a librandomx_arq.a.syms \
  librandomx_panthera.a librandomx_panthera.a.syms

build-stamp.c: $(cpuminer_OBJECTS) libcurvehash_secp256k1.a $(RANDOMX_LIBS)
	$(AM_V_GEN)printf 'const char build_stamp_date[] = "%s";\n' \
	  "`date '+%b %d %Y %H:%M:%S'`" > $@

build-stamp.$(OBJEXT): build-stamp.c
	$(AM_V_CC)$(CC) $(CFLAGS) -c -o $@ build-stamp.c
cpuminer_CPPFLAGS = @LIBCURL_CPPFLAGS@ $(ALL_INCLUDES) $(RANDOMX_VARIANT_DEFINES)
cpuminer_CFLAGS = -Wno-pointer-sign -Wno-pointer-to-int-cast $(disable_flags)

if ARCH_ARM64
   cpuminer_CFLAGS += -flax-vector-conversions
endif

if HAVE_WINDOWS

# use to profile an object
# gprof_cflags = -pg -g3
# cpuminer_LDFLAGS += -pg
# cpuminer_CFLAGS += -fno-inline-functions -static

# copy/paste from generated Makefile
common_ccflags = $(DEFS) $(ALL_INCLUDES) $(cpuminer_CPPFLAGS) $(CPPFLAGS) $(cpuminer_CFLAGS) $(CFLAGS)

# special CFLAGS (if you find a simpler way to do that tell me ;)
cpuminer-neoscrypt.o: neoscrypt.c
	@echo "CUSTOM ${@}: ${filter %.o,${^}} ${filter %.c,${^}}"
	$(CC) $(common_ccflags) -g -O3 $(gprof_cflags) -MT $@ -MD -MP -c -o $@ $<

endif
