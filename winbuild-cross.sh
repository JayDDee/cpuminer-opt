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

export LDFLAGS="-L$LOCAL_LIB/curl/lib/.libs -L$LOCAL_LIB/gmp/.libs -L$LOCAL_LIB/openssl"

export CONFIGURE_ARGS="--with-curl=$LOCAL_LIB/curl --with-crypto=$LOCAL_LIB/openssl --host=x86_64-w64-mingw32"

# make link to local gmp header file.
ln -s $LOCAL_LIB/gmp/gmp.h ./gmp.h

# edit configure to fix pthread lib name for Windows.
#sed -i 's/"-lpthread"/"-lpthreadGC2"/g' configure.ac

# make release directory and copy selected DLLs.
mkdir release
cp README.txt release/
cp README.md release/
cp RELEASE_NOTES release/
cp /usr/x86_64-w64-mingw32/lib/zlib1.dll release/
cp /usr/x86_64-w64-mingw32/lib/libwinpthread-1.dll release/
cp /usr/lib/gcc/x86_64-w64-mingw32/7.3-win32/libstdc++-6.dll release/
cp /usr/lib/gcc/x86_64-w64-mingw32/7.3-win32/libgcc_s_seh-1.dll release/
cp $LOCAL_LIB/openssl/libcrypto-1_1-x64.dll release/
cp $LOCAL_LIB/curl/lib/.libs/libcurl-4.dll release/

make distclean || echo clean
rm -f config.status
./autogen.sh || echo done
CFLAGS="-O3 -march=znver1 -Wall" ./configure $CONFIGURE_ARGS
make -j 16
strip -s cpuminer.exe
mv cpuminer.exe release/cpuminer-zen.exe

#make clean || echo clean
#CFLAGS="-O3 -march=corei7-avx -msha -Wall" ./configure $CONFIGURE_ARGS
#make
#strip -s cpuminer.exe
#mv cpuminer.exe release/cpuminer-avx-sha.exe

make clean || echo clean
rm -f config.status
CFLAGS="-O3 -march=core-avx2 -Wall" ./configure $CONFIGURE_ARGS
make -j 16
strip -s cpuminer.exe
mv cpuminer.exe release/cpuminer-avx2.exe

#make clean || echo clean
#rm -f config.status
#CFLAGS="-O3 -march=znver1 -Wall" ./configure $CONFIGURE_ARGS
#make -j 
#strip -s cpuminer.exe
#mv cpuminer.exe release/cpuminer-aes-sha.exe


make clean || echo clean
rm -f config.status
CFLAGS="-O3 -march=corei7-avx -Wall" ./configure $CONFIGURE_ARGS 
make -j 16
strip -s cpuminer.exe
mv cpuminer.exe release/cpuminer-avx.exe

# -march=westmere is supported in gcc5
make clean || echo clean
rm -f config.status
CFLAGS="-O3 -march=westmere -Wall" ./configure $CONFIGURE_ARGS
#CFLAGS="-O3 -maes -msse4.2 -Wall" ./configure $CONFIGURE_ARGS
make -j 16
strip -s cpuminer.exe
mv cpuminer.exe release/cpuminer-aes-sse42.exe

#make clean || echo clean
#rm -f config.status
#CFLAGS="-O3 -march=corei7 -Wall" ./configure $CONFIGURE_ARGS
#make 
#strip -s cpuminer.exe
#mv cpuminer.exe release/cpuminer-sse42.exe

#make clean || echo clean
#rm -f config.status
#CFLAGS="-O3 -march=core2 -Wall" ./configure $CONFIGURE_ARGS
#make 
#strip -s cpuminer.exe
#mv cpuminer.exe release/cpuminer-ssse3.exe
#make clean || echo clean

make clean || echo clean
rm -f config.status
CFLAGS="-O3 -msse2 -Wall" ./configure $CONFIGURE_ARGS
make -j 16
strip -s cpuminer.exe
mv cpuminer.exe release/cpuminer-sse2.exe
make clean || echo clean

