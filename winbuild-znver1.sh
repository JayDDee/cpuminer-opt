#!/bin/bash

rm -f cpuminer.exe || echo rm miner
rm -f cpuminer-znver1.exe || echo rm final miner
make distclean || echo clean
rm -f config.status
./autogen.sh || echo done
CFLAGS="-O3 -march=znver1 -Wall" CXXFLAGS="$CFLAGS -std=gnu++11 -fpermissive" ./configure --with-curl
make -j 4
strip -s cpuminer.exe
mv cpuminer.exe cpuminer-znver1.exe