#!/bin/bash
#
# Script for building Windows binaries release package using mingw.
# Requires a custom mingw environment, not intended for users.
#
# Compiles Windows EXE files for selected CPU architectures and copies them
# into a release folder ready to be zipped and uploaded.
#
# Builds are STATIC: the .exe imports only OS-provided DLLs, so nothing has to
# be shipped alongside it.
#
# Usage:
#   ./winbuild-cross.sh              build every target
#   ./winbuild-cross.sh avx512-sha-vaes   build just one (name as in release/)
#
# Prerequisites, once:
#   - mingw-w64 cross toolchain
#   - libcurl cross-built static into $LOCAL_LIB/curl
#     (--with-schannel --with-zlib --disable-shared -> Windows-native TLS,
#      so there is no OpenSSL DLL to ship)
#   - GMP cross-built into $LOCAL_LIB/gmp (-lgmp is unconditional in
#     Makefile.am; no distro ships a mingw build of it)

set -u

# Overridable so the cross-deps can live somewhere a home tidy-up will not eat
# them, e.g. LOCAL_LIB=~/cpuminer-opt/winbuild/lib. Default unchanged.
export LOCAL_LIB="${LOCAL_LIB:-$HOME/usr/lib}"
export CURL_PREFIX="$LOCAL_LIB/curl"
CROSS=x86_64-w64-mingw32

# ---------------------------------------------------------------- toolchain
#
# --build is MANDATORY under WSL. Interop lets Linux execute the .exe that
# configure just built, so autoconf concludes it is NOT cross compiling and
# then fails in confusing ways. build-armv8.sh passes --build for the same
# reason.
export CONFIGURE_ARGS="--with-curl=$CURL_PREFIX --host=$CROSS --build=x86_64-pc-linux-gnu"

# libcurl here is static, so curl.h must NOT declare its symbols dllimport.
# Without -DCURL_STATICLIB the link dies on undefined __imp_curl_easy_init and
# friends -- that error means this flag is missing, nothing else.
#
# -I$LOCAL_LIB/gmp picks up the cross-built gmp.h (m7m needs GMP).
export DEFAULT_CFLAGS="-maes -O3 -Wall -DCURL_STATICLIB -I$LOCAL_LIB/gmp"
export DEFAULT_CFLAGS_OLD="-O3 -Wall -DCURL_STATICLIB -I$LOCAL_LIB/gmp"

# -static, or the .exe needs zlib1.dll, libwinpthread-1.dll and
# libgcc_s_seh-1.dll, none of which a stock Windows has. Linking them in costs
# ~65 KB and removes the whole shipping problem.
export LDFLAGS="-static -L$LOCAL_LIB/gmp/.libs"

# A static libcurl does not pull its own dependencies, so name them. Ask
# curl-config rather than hardcoding: the set depends on how curl was built
# (schannel vs openssl, zlib or not).
#   -> -lsecur32 -lbcrypt -ladvapi32 -lcrypt32 -lz -lws2_32 -liphlpapi
if [ -x "$CURL_PREFIX/bin/curl-config" ]; then
   export LIBS="$( "$CURL_PREFIX/bin/curl-config" --static-libs \
                   | sed 's|[^ ]*libcurl\.a||' )"
else
   echo "ERROR: $CURL_PREFIX/bin/curl-config not found." >&2
   echo "       Cross-build a static libcurl into $CURL_PREFIX first:" >&2
   echo "       ./configure --host=$CROSS --build=x86_64-pc-linux-gnu \\" >&2
   echo "                   --with-schannel --with-zlib --disable-shared" >&2
   exit 1
fi

# ------------------------------------------------------------------- build

TARGET="${1:-all}"
JOBS="${JOBS:-$(nproc)}"        # JOBS=4 to leave the box usable while building

mkdir -p release
cp README.txt README.md RELEASE_NOTES verthash-help.txt release/

# $1 = release name, $2 = -march/-mtune flags, $3 = flag set
build() {
   local name="$1" arch="$2" base="$3"

   if [ "$TARGET" != "all" ] && [ "$TARGET" != "$name" ]; then
      return 0
   fi
   echo "=== building cpuminer-$name"

   make distclean > /dev/null 2>&1 || true
   rm -f config.status
   CFLAGS="$arch $base" ./configure $CONFIGURE_ARGS > /dev/null || return 1
   make -j"$JOBS" || return 1
   $CROSS-strip -s cpuminer.exe          # host strip cannot handle PE
   mv cpuminer.exe "release/cpuminer-$name.exe"
}

./autogen.sh || echo done

# AVX512 SHA VAES: Intel Core Icelake, Rocketlake
build avx512-sha-vaes "-march=icelake-client" "$DEFAULT_CFLAGS"
# AVX512 AES: Intel Core HEDT Skylake-X, Cascadelake
build avx512          "-march=skylake-avx512" "$DEFAULT_CFLAGS"
# AVX2 SHA VAES: Intel Alderlake, AMD Zen3
build avx2-sha-vaes   "-mavx2 -msha -mvaes"   "$DEFAULT_CFLAGS"
# AVX2 AES SHA: AMD Zen1
build avx2-sha        "-march=znver1"         "$DEFAULT_CFLAGS"
# AVX2 AES: Intel Core Haswell, Skylake, Kabylake, Coffeelake, Cometlake
build avx2            "-march=core-avx2"      "$DEFAULT_CFLAGS"
# AVX AES: Intel Sandybridge, Ivybridge
build avx             "-march=corei7-avx -maes" "$DEFAULT_CFLAGS_OLD"
# SSE4.2 AES: Intel Westmere
build aes-sse42       "-march=westmere -maes" "$DEFAULT_CFLAGS_OLD"
# Generic SSE2
build sse2            "-msse2"                "$DEFAULT_CFLAGS_OLD"

echo
echo "=== release/"
ls -l release/*.exe 2>/dev/null

# Verify a build the way a user would run it: with a stripped PATH. Git Bash
# ships its own zlib1.dll in mingw64/bin, so a dynamically-linked .exe runs
# fine from a developer prompt and fails for everyone else.
#
#   env -i PATH="C:\\Windows\\System32" SYSTEMROOT="C:\\Windows" \
#       ./cpuminer.exe -a curvehash --benchmark -t 2
#
# With -static the only imports should be OS-provided:
#   ADVAPI32 bcrypt CRYPT32 IPHLPAPI KERNEL32 msvcrt Secur32 USER32 WS2_32
