#!/bin/bash

LOCAL_LIB="$HOME/usr/lib"

export LDFLAGS="-L$LOCAL_LIB/curl/lib/.libs -L$LOCAL_LIB/gmp/.libs -L$LOCAL_LIB/openssl"

F="--with-curl=$LOCAL_LIB/curl --with-crypto=$LOCAL_LIB/openssl --host=x86_64-w64-mingw32"

sed -i 's/"-lpthread"/"-lpthreadGC2"/g' configure.ac

mkdir release
cp README.txt release/
cp /usr/x86_64-w64-mingw32/lib/zlib1.dll release/
cp /usr/x86_64-w64-mingw32/lib/libwinpthread-1.dll release/
cp /usr/lib/gcc/x86_64-w64-mingw32/5.3-win32/libstdc++-6.dll release/
cp /usr/lib/gcc/x86_64-w64-mingw32/5.3-win32/libgcc_s_seh-1.dll release/
cp $LOCAL_LIB/openssl/libcrypto-1_1-x64.dll release/
cp $LOCAL_LIB/curl/lib/.libs/libcurl-4.dll release/

make distclean || echo clean
rm -f config.status
./autogen.sh || echo done
CFLAGS="-O3 -march=core-avx2 -msha -Wall" ./configure $F
make 
strip -s cpuminer.exe
mv cpuminer.exe release/cpuminer-avx2-sha.exe

#make clean || echo clean
#rm -f config.status
#CFLAGS="-O3 -march=core-avx2 -Wall -DFOUR_WAY" ./configure $F
#make
#mv cpuminer.exe release/cpuminer-4way.exe

#make clean || echo clean
#CFLAGS="-O3 -march=corei7-avx -msha -Wall" ./configure $F
#make
#strip -s cpuminer.exe
#mv cpuminer.exe release/cpuminer-avx-sha.exe

make clean || echo clean
rm -f config.status
CFLAGS="-O3 -march=core-avx2 -Wall" ./configure $F 
make 
strip -s cpuminer.exe
mv cpuminer.exe release/cpuminer-avx2.exe

#make clean || echo clean
#rm -f config.status
#CFLAGS="-O3 -march=znver1 -Wall" ./configure $F
#make -j 
#strip -s cpuminer.exe
#mv cpuminer.exe release/cpuminer-aes-sha.exe


make clean || echo clean
rm -f config.status
CFLAGS="-O3 -march=corei7-avx -Wall" ./configure $F 
make 
strip -s cpuminer.exe
mv cpuminer.exe release/cpuminer-aes-avx.exe

make clean || echo clean
rm -f config.status
CFLAGS="-O3 -maes -msse4.2 -Wall" ./configure $F
make 
strip -s cpuminer.exe
mv cpuminer.exe release/cpuminer-aes-sse42.exe

#make clean || echo clean
#rm -f config.status
#CFLAGS="-O3 -march=corei7 -Wall" ./configure $F
#make 
#strip -s cpuminer.exe
#mv cpuminer.exe release/cpuminer-sse42.exe

make clean || echo clean
rm -f config.status
CFLAGS="-O3 -march=core2 -Wall" ./configure $F
make 
strip -s cpuminer.exe
mv cpuminer.exe release/cpuminer-sse2.exe
make clean || echo clean

