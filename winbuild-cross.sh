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
export CONFIGURE_ARGS="--with-curl=$LOCAL_LIB/curl --with-crypto=$LOCAL_LIB/openssl --host=x86_64-w64-mingw32"
export MINGW_LIB="/usr/x86_64-w64-mingw32/lib"
# set correct gcc version
export GCC_MINGW_LIB="/usr/lib/gcc/x86_64-w64-mingw32/9.3-win32"
# used by GCC
export LDFLAGS="-L$LOCAL_LIB/curl/lib/.libs -L$LOCAL_LIB/gmp/.libs -L$LOCAL_LIB/openssl"

# make link to local gmp header file.
ln -s $LOCAL_LIB/gmp/gmp.h ./gmp.h

# edit configure to fix pthread lib name for Windows.
#sed -i 's/"-lpthread"/"-lpthreadGC2"/g' configure.ac

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
cp $LOCAL_LIB/openssl/libcrypto-1_1-x64.dll release/
cp $LOCAL_LIB/curl/lib/.libs/libcurl-4.dll release/

# Start building...

# Icelake AVX512 SHA VAES
./clean-all.sh || echo clean
rm -f config.status
./autogen.sh || echo done
CFLAGS="-O3 -march=icelake-client -Wall" ./configure $CONFIGURE_ARGS
make -j 8
strip -s cpuminer.exe
mv cpuminer.exe release/cpuminer-avx512-sha-vaes.exe

# Rocketlake AVX512 SHA AES
make clean || echo clean
rm -f config.status
CFLAGS="-O3 -march=cascadelake -msha -Wall" ./configure $CONFIGURE_ARGS
#CFLAGS="-O3 -march=rocketlake -Wall" ./configure $CONFIGURE_ARGS
make -j 8
strip -s cpuminer.exe
mv cpuminer.exe release/cpuminer-avx512-sha.exe

# Zen1 AVX2 AES SHA
make clean || echo clean
rm -f config.status
CFLAGS="-O3 -march=znver1 -Wall" ./configure $CONFIGURE_ARGS
make -j 8
strip -s cpuminer.exe
mv cpuminer.exe release/cpuminer-zen.exe

# Zen3 AVX2 SHA VAES
make clean || echo clean
rm -f config.status
CFLAGS="-O3 -march=znver2 -mvaes -Wall" ./configure $CONFIGURE_ARGS
# CFLAGS="-O3 -march=znver3 -Wall" ./configure $CONFIGURE_ARGS
make -j 8
strip -s cpuminer.exe
mv cpuminer.exe release/cpuminer-zen3.exe

# Slylake-X AVX512 AES
# mingw won't compile avx512 without -fno-asynchronous-unwind-tables
make clean || echo clean
rm -f config.status
CFLAGS="-O3 -march=skylake-avx512 -Wall" ./configure $CONFIGURE_ARGS
#CFLAGS="-O3 -march=skylake-avx512 -Wall -fno-asynchronous-unwind-tables" ./configure $CONFIGURE_ARGS
make -j 8
strip -s cpuminer.exe
mv cpuminer.exe release/cpuminer-avx512.exe

# Haswell AVX2 AES
make clean || echo clean
rm -f config.status
# GCC 9 doesn't include AES in -march=core-avx2
CFLAGS="-O3 -march=core-avx2 -maes -Wall" ./configure $CONFIGURE_ARGS
make -j 8
strip -s cpuminer.exe
mv cpuminer.exe release/cpuminer-avx2.exe

# Sandybridge AVX AES
make clean || echo clean
rm -f config.status
# -march=corei7-avx still includes aes, but just in case
CFLAGS="-O3 -march=corei7-avx -maes -Wall" ./configure $CONFIGURE_ARGS 
make -j 8
strip -s cpuminer.exe
mv cpuminer.exe release/cpuminer-avx.exe

# Westmere SSE4.2 AES
make clean || echo clean
rm -f config.status
CFLAGS="-O3 -march=westmere -maes -Wall" ./configure $CONFIGURE_ARGS
#CFLAGS="-O3 -maes -msse4.2 -Wall" ./configure $CONFIGURE_ARGS
make -j 8
strip -s cpuminer.exe
mv cpuminer.exe release/cpuminer-aes-sse42.exe

# Nehalem SSE4.2
#make clean || echo clean
#rm -f config.status
#CFLAGS="-O3 -march=corei7 -Wall" ./configure $CONFIGURE_ARGS
#make 
#strip -s cpuminer.exe
#mv cpuminer.exe release/cpuminer-sse42.exe

# Core2 SSSE3
#make clean || echo clean
#rm -f config.status
#CFLAGS="-O3 -march=core2 -Wall" ./configure $CONFIGURE_ARGS
#make 
#strip -s cpuminer.exe
#mv cpuminer.exe release/cpuminer-ssse3.exe
#make clean || echo clean

# Generic SSE2
make clean || echo clean
rm -f config.status
CFLAGS="-O3 -msse2 -Wall" ./configure $CONFIGURE_ARGS
make -j 8
strip -s cpuminer.exe
mv cpuminer.exe release/cpuminer-sse2.exe
make clean || echo clean

