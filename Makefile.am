
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

cpuminer_SOURCES = \
  dummy.cpp \
  cpu-miner.c \
  util.c \
  api.c \
  sysinfos.c \
  algo-gate-api.c\
  malloc-huge.c \
  algo/argon2d/argon2d-gate.c \
  algo/argon2d/blake2/blake2b.c \
  algo/argon2d/argon2d/argon2.c \
  algo/argon2d/argon2d/core.c \
  algo/argon2d/argon2d/opt.c \
  algo/argon2d/argon2d/argon2d_thread.c \
  algo/argon2d/argon2d/encoding.c \
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
  algo/echo/sph_echo.c \
  algo/echo/echo-hash-4way.c \
  algo/echo/aes_ni/hash.c\
  algo/gost/sph_gost.c \
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
  algo/sha/sha256dt.c \
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
  algo/whirlpool/sph_whirlpool.c \
  algo/whirlpool/whirlpool-gate.c \
  algo/whirlpool/whirlpool.c \
  algo/whirlpool/whirlpoolx.c \
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
  algo/x22/x22i-4way.c \
  algo/x22/x22i.c \
  algo/x22/x22i-gate.c \
  algo/x22/x25x.c \
  algo/x22/x25x-4way.c \
  algo/yespower/yespower-gate.c \
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
cpuminer_LDADD	= $(EXTRA_LIBS) @LIBCURL@ -ljansson @PTHREAD_LIBS@ @WS2_LIBS@ -lgmp
cpuminer_CPPFLAGS = @LIBCURL_CPPFLAGS@ $(ALL_INCLUDES)
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
