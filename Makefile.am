
if WANT_JANSSON
JANSSON_INCLUDES= -I$(top_srcdir)/compat/jansson
else
JANSSON_INCLUDES=
endif

EXTRA_DIST	= example-cfg.json nomacro.pl

SUBDIRS		= compat

ALL_INCLUDES	= @PTHREAD_FLAGS@ -fno-strict-aliasing $(JANSSON_INCLUDES) -I.

bin_PROGRAMS	= cpuminer

dist_man_MANS	= cpuminer.1

#  algo/echo/aes_ni/hash.c\
#  algo/groestl/aes_ni/hash-groestl.c \
#  algo/groestl/aes_ni/hash-groestl256.c \
#  algo/shavite/sph-shavite-aesni.c \
#  algo/luffa/sse2/luffa_for_sse2.c \
#  algo/simd/sse2/nist.c \
#  algo/simd/sse2/vector.c \
#  algo/yescrypt/yescrypt-simd.c \
#
cpuminer_SOURCES = \
  cpu-miner.c \
  util.c \
  uint256.cpp \
  api.c \
  sysinfos.c \
  algo-gate-api.c\
  crypto/blake2s.c \
  crypto/oaes_lib.c \
  crypto/c_keccak.c \
  crypto/c_groestl.c \
  crypto/c_blake256.c \
  crypto/c_jh.c \
  crypto/c_skein.c \
  crypto/hash.c \
  crypto/aesb.c \
  crypto/magimath.cpp \
  algo/argon2/argon2a.c \
  algo/argon2/ar2/argon2.c \
  algo/argon2/ar2/ar2-best.c \
  algo/argon2/ar2/cores.c \
  algo/argon2/ar2/ar2-scrypt-jane.c \
  algo/argon2/ar2/blake2b.c \
  algo/blake/sph_blake.c \
  algo/blake/blake-hash-4way.c \
  algo/blake/blake-gate.c \
  algo/blake/blake.c \
  algo/blake/blake-4way.c \
  algo/blake/sph_blake2b.c \
  algo/blake/blake2b.c \
  algo/blake/blake2s.c \
  algo/blake/blakecoin-gate.c \
  algo/blake/mod_blakecoin.c \
  algo/blake/blakecoin.c \
  algo/blake/blakecoin-4way.c \
  algo/blake/decred-gate.c \
  algo/blake/decred.c \
  algo/blake/decred-4way.c \
  algo/blake/pentablake-gate.c \
  algo/blake/pentablake-4way.c \
  algo/blake/pentablake.c \
  algo/bmw/sph_bmw.c \
  algo/bmw/bmw-hash-4way.c \
  algo/bmw/bmw256.c \
  algo/cryptonight/cryptolight.c \
  algo/cryptonight/cryptonight-common.c\
  algo/cryptonight/cryptonight-aesni.c\
  algo/cryptonight/cryptonight.c\
  algo/cubehash/sph_cubehash.c \
  algo/cubehash/sse2/cubehash_sse2.c\
  algo/echo/sph_echo.c \
  algo/gost/sph_gost.c \
  algo/groestl/sph_groestl.c \
  algo/groestl/groestl.c \
  algo/groestl/myr-groestl.c \
  algo/fugue/sph_fugue.c \
  algo/hamsi/sph_hamsi.c \
  algo/haval/haval.c\
  algo/heavy/sph_hefty1.c \
  algo/heavy/heavy.c \
  algo/hodl/aes.c \
  algo/hodl/hodl-gate.c \
  algo/hodl/hodl-wolf.c \
  algo/hodl/sha512_avx.c \
  algo/hodl/sha512_avx2.c \
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
  algo/keccak/sse2/keccak.c \
  algo/lbry.c \
  algo/luffa/sph_luffa.c \
  algo/luffa/luffa.c \
  algo/lyra2/lyra2.c \
  algo/lyra2/sponge.c \
  algo/lyra2/lyra2rev2-gate.c \
  algo/lyra2/lyra2rev2.c \
  algo/lyra2/lyra2rev2-4way.c \
  algo/lyra2/lyra2re.c \
  algo/lyra2/lyra2z-gate.c \
  algo/lyra2/lyra2z.c \
  algo/lyra2/lyra2z-4way.c \
  algo/lyra2/lyra2z330.c \
  algo/lyra2/lyra2h-gate.c \
  algo/lyra2/lyra2h.c \
  algo/lyra2/lyra2h-4way.c \
  algo/lyra2/allium-gate.c \
  algo/lyra2/allium.c \
  algo/m7m.c \
  algo/neoscrypt/neoscrypt.c \
  algo/nist5/nist5-gate.c \
  algo/nist5/nist5-4way.c \
  algo/nist5/nist5.c \
  algo/nist5/zr5.c \
  algo/pluck.c \
  algo/quark/quark-gate.c \
  algo/quark/quark.c \
  algo/quark/quark-4way.c \
  algo/ripemd/sph_ripemd.c \
  algo/scrypt.c \
  algo/scryptjane/scrypt-jane.c \
  algo/sha/sph_sha2.c \
  algo/sha/sph_sha2big.c \
  algo/sha/sha2.c \
  algo/sha/sha256t.c \
  algo/shabal/sph_shabal.c \
  algo/shabal/shabal-hash-4way.c \
  algo/shavite/sph_shavite.c \
  algo/shavite/shavite.c \
  algo/simd/sph_simd.c \
  algo/skein/sph_skein.c \
  algo/skein/skein-hash-4way.c \
  algo/skein/skein.c \
  algo/skein/skein-4way.c \
  algo/skein/skein-gate.c \
  algo/skein/skein2.c \
  algo/skein/skein2-4way.c \
  algo/skein/skein2-gate.c \
  algo/sm3/sm3.c \
  algo/sm3/sm3-hash-4way.c \
  algo/tiger/sph_tiger.c \
  algo/whirlpool/sph_whirlpool.c \
  algo/whirlpool/whirlpool-hash-4way.c \
  algo/whirlpool/whirlpool-gate.c \
  algo/whirlpool/whirlpool-4way.c \
  algo/whirlpool/whirlpool.c \
  algo/whirlpool/whirlpoolx.c \
  algo/yescrypt/yescrypt.c \
  algo/yescrypt/sha256_Y.c \
  algo/yescrypt/yescrypt-best.c \
  algo/yespower/yespower-gate.c \
  algo/yespower/yespower-blake2b.c \
  algo/yespower/crypto/blake2b-yp.c \
  algo/yespower/sha256_p.c \
  algo/yespower/yespower-opt.c

disable_flags =

if USE_ASM
   cpuminer_SOURCES += asm/neoscrypt_asm.S
if ARCH_x86
   cpuminer_SOURCES += asm/sha2-x86.S asm/scrypt-x86.S asm/aesb-x86.S
endif
if ARCH_x86_64
   cpuminer_SOURCES += asm/sha2-x64.S asm/scrypt-x64.S asm/aesb-x64.S
endif
if ARCH_ARM
   cpuminer_SOURCES += asm/sha2-arm.S asm/scrypt-arm.S
endif
else
   disable_flags += -DNOASM
endif

if HAVE_WINDOWS
   cpuminer_SOURCES += compat/winansi.c
endif

cpuminer_LDFLAGS	= @LDFLAGS@
cpuminer_LDADD	= @LIBCURL@ @JANSSON_LIBS@ @PTHREAD_LIBS@ @WS2_LIBS@ -lssl -lcrypto -lgmp
cpuminer_CPPFLAGS = @LIBCURL_CPPFLAGS@ $(ALL_INCLUDES)
cpuminer_CFLAGS   = -Wno-pointer-sign -Wno-pointer-to-int-cast $(disable_flags)

if HAVE_WINDOWS
cpuminer_CFLAGS += -Wl,--stack,10485760
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
