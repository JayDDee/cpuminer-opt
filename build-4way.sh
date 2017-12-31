#!/bin/bash

# Linux build

make distclean || echo clean

rm -f config.status
./autogen.sh || echo done

#CFLAGS="-O3 -march=native -Wall -DFOUR_WAY" ./configure --with-curl --with-crypto=$HOME/usr
CFLAGS="-O3 -march=native -Wall -DFOUR_WAY" ./configure --with-curl

make -j 4

strip -s cpuminer
