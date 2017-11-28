#!/bin/bash

make distclean || echo clean
rm -f config.status
./autogen.sh || echo done
CFLAGS="-O3 -march=core-avx2 -Wall -DUSE_SPH_SHA -DFOUR_WAY" ./configure --with-curl
make -j 4
strip -s cpuminer.exe
mv cpuminer.exe cpuminer-4way.exe

make clean
rm -f config.status
./autogen.sh || echo done
CFLAGS="-O3 -march=core-avx2 -Wall -DUSE_SPH_SHA" ./configure --with-curl
make -j 4
strip -s cpuminer.exe
mv cpuminer.exe cpuminer-aes-avx2.exe

make clean || echo clean
rm -f config.status
./autogen.sh || echo done
CFLAGS="-O3 -march=corei7-avx -Wall -DUSE_SPH_SHA" ./configure --with-curl
make -j 4
strip -s cpuminer.exe
mv cpuminer.exe cpuminer-aes-avx.exe

make clean || echo clean
rm -f config.status
./autogen.sh || echo done
CFLAGS="-O3 -maes -msse4.2 -Wall -DUSE_SPH_SHA" ./configure --with-curl
make -j 4
strip -s cpuminer.exe
mv cpuminer.exe cpuminer-aes-sse42.exe

make clean || echo clean
rm -f config.status
./autogen.sh || echo done
CFLAGS="-O3 -march=corei7 -Wall -DUSE_SPH_SHA" ./configure --with-curl
make -j 4
strip -s cpuminer.exe
mv cpuminer.exe cpuminer-sse42.exe

make clean || echo clean
rm -f config.status
./autogen.sh || echo done
CFLAGS="-O3 -march=core2 -Wall -DUSE_SPH_SHA" ./configure --with-curl
make -j 4
strip -s cpuminer.exe
mv cpuminer.exe cpuminer-sse2.exe

make clean || echo done


