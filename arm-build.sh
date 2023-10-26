#!/bin/bash

# Linux build

make distclean || echo clean

rm -f config.status
./autogen.sh || echo done

CFLAGS="-O3 -march=native -Wall -flax-vector-conversions" ./configure  --with-curl 

make -j $nproc

strip -s cpuminer
