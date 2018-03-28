#!/bin/bash

make distclean || echo clean
rm -f config.status
./autogen.sh || echo done
CFLAGS="-O3 -march=core-avx2 -Wall" ./configure --with-curl
make -j 4
strip -s cpuminer.exe
mv cpuminer.exe cpuminer-aes-avx2.exe
strip -s cpuminer
mv cpuminer cpuminer-avx2

make clean || echo clean
rm -f config.status
./autogen.sh || echo done
CFLAGS="-O3 -march=corei7-avx -Wall" ./configure --with-curl
make -j 4
strip -s cpuminer.exe
mv cpuminer.exe cpuminer-aes-avx.exe
strip -s cpuminer
mv cpuminer cpuminer-aes-avx

make clean || echo clean
rm -f config.status
./autogen.sh || echo done
CFLAGS="-O3 -maes -msse4.2 -Wall" ./configure --with-curl
make -j 4
strip -s cpuminer.exe
mv cpuminer.exe cpuminer-aes-sse42.exe
strip -s cpuminer
mv cpuminer cpuminer-aes-sse42

make clean || echo clean
rm -f config.status
./autogen.sh || echo done
CFLAGS="-O3 -march=corei7 -Wall" ./configure --with-curl
make -j 4
strip -s cpuminer.exe
mv cpuminer.exe cpuminer-sse42.exe
strip -s cpuminer
mv cpuminer cpuminer-sse42

make clean || echo clean
rm -f config.status
./autogen.sh || echo done
CFLAGS="-O3 -march=core2 -Wall" ./configure --with-curl
make -j 4
strip -s cpuminer.exe
mv cpuminer.exe cpuminer-ssse3.exe
strip -s cpuminer
mv cpuminer cpuminer-ssse3

make clean || echo clean
rm -f config.status
./autogen.sh || echo done
CFLAGS="-O3 -msse2 -Wall" ./configure --with-curl
make -j 4
strip -s cpuminer.exe
mv cpuminer.exe cpuminer-sse2.exe
strip -s cpuminer
mv cpuminer cpuminer-sse2

make clean || echo done


