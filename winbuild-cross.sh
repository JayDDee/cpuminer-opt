#!/bin/bash
#
# Script for building Windows binaries release package using mingw.
# Requires a custom mingw environment, not intended for users.
#
# Compiles Windows EXE files for selected CPU architectures, copies them
# as well as some DLLs that aren't available in most Windows environments
# into a release folder ready to be zipped and uploaded.

# define some local variables

export LOCAL_LIB="$HOME/usr/lib"
export CONFIGURE_ARGS="--with-curl=$LOCAL_LIB/curl --host=x86_64-w64-mingw32"
export MINGW_LIB="/usr/x86_64-w64-mingw32/lib"
# set correct gcc version
export GCC_MINGW_LIB="/usr/lib/gcc/x86_64-w64-mingw32/9.3-win32"
# used by GCC
export LDFLAGS="-L$LOCAL_LIB/curl/lib/.libs -L$LOCAL_LIB/gmp/.libs"
export DEFAULT_CFLAGS="-maes -O3 -Wall"
export DEFAULT_CFLAGS_OLD="-O3 -Wall"

# make link to local gmp header file.
ln -s $LOCAL_LIB/gmp/gmp.h ./gmp.h

# make release directory and copy selected DLLs.

rm -rf release > /dev/null
mkdir release

cp README.txt release/
cp README.md release/
cp RELEASE_NOTES release/
cp verthash-help.txt release/
cp $MINGW_LIB/zlib1.dll release/
cp $MINGW_LIB/libwinpthread-1.dll release/
cp $GCC_MINGW_LIB/libstdc++-6.dll release/
cp $GCC_MINGW_LIB/libgcc_s_seh-1.dll release/
cp $LOCAL_LIB/curl/lib/.libs/libcurl-4.dll release/

# Start building...

# AVX512 SHA VAES: Intel Core Icelake, Rocketlake
./clean-all.sh || echo clean
rm -f config.status
./autogen.sh || echo done
CFLAGS="-march=icelake-client $DEFAULT_CFLAGS" ./configure $CONFIGURE_ARGS
make -j 8
strip -s cpuminer.exe
mv cpuminer.exe release/cpuminer-avx512-sha-vaes.exe

# AVX512 AES: Intel Core HEDT Slylake-X, Cascadelake 
make clean || echo clean
rm -f config.status
CFLAGS="-march=skylake-avx512 $DEFAULT_CFLAGS" ./configure $CONFIGURE_ARGS
make -j 8
strip -s cpuminer.exe
mv cpuminer.exe release/cpuminer-avx512.exe

# AVX2 SHA VAES: Intel Alderlake, AMD Zen3
make clean || echo done
rm -f config.status
CFLAGS="-mavx2 -msha -mvaes $DEFAULT_CFLAGS" ./configure $CONFIGURE_ARGS
make -j 8
strip -s cpuminer.exe
mv cpuminer.exe release/cpuminer-avx2-sha-vaes.exe

# AVX2 AES SHA: AMD Zen1
make clean || echo clean
rm -f config.status
CFLAGS="-march=znver1 $DEFAULT_CFLAGS" ./configure $CONFIGURE_ARGS
make -j 8
strip -s cpuminer.exe
mv cpuminer.exe release/cpuminer-avx2-sha.exe

# AVX2 AES: Intel Core Haswell, Skylake, Kabylake, Coffeelake, Cometlake
make clean || echo clean
rm -f config.status
CFLAGS="-march=core-avx2 $DEFAULT_CFLAGS" ./configure $CONFIGURE_ARGS
make -j 8
strip -s cpuminer.exe
mv cpuminer.exe release/cpuminer-avx2.exe

# AVX AES: Intel Sandybridge, Ivybridge
make clean || echo clean
rm -f config.status
CFLAGS="-march=corei7-avx -maes $DEFAULT_CFLAGS_OLD" ./configure $CONFIGURE_ARGS 
make -j 8
strip -s cpuminer.exe
mv cpuminer.exe release/cpuminer-avx.exe

# SSE4.2 AES: Intel Westmere
make clean || echo clean
rm -f config.status
CFLAGS="-march=westmere -maes $DEFAULT_CFLAGS_OLD" ./configure $CONFIGURE_ARGS
make -j 8
strip -s cpuminer.exe
mv cpuminer.exe release/cpuminer-aes-sse42.exe

# Nehalem SSE4.2
#make clean || echo clean
#rm -f config.status
#CFLAGS="$DEFAULT_CFLAGS_OLD -march=corei7" ./configure $CONFIGURE_ARGS
#make 
#strip -s cpuminer.exe
#mv cpuminer.exe release/cpuminer-sse42.exe

# Core2 SSSE3
#make clean || echo clean
#rm -f config.status
#CFLAGS="$DEFAULT_CFLAGS_OLD -march=core2" ./configure $CONFIGURE_ARGS
#make 
#strip -s cpuminer.exe
#mv cpuminer.exe release/cpuminer-ssse3.exe
#make clean || echo clean

# Generic SSE2
make clean || echo clean
rm -f config.status
CFLAGS="-msse2 $DEFAULT_CFLAGS_OLD" ./configure $CONFIGURE_ARGS
make -j 8
strip -s cpuminer.exe
mv cpuminer.exe release/cpuminer-sse2.exe
#make clean || echo clean

# Native with CPU groups ennabled
#make clean || echo clean
#rm -f config.status
#CFLAGS="-march=native $DEFAULT_CFLAGS_OLD" ./configure $CONFIGURE_ARGS
#make -j 8
#strip -s cpuminer.exe

