#!/bin/bash

#if [ "$OS" = "Windows_NT" ]; then
#    ./mingw64.sh
#    exit 0
#fi

# Linux build

make distclean || echo clean

rm -f config.status
./autogen.sh || echo done

# Ubuntu 10.04 (gcc 4.4)
# extracflags="-O3 -march=native -Wall -D_REENTRANT -funroll-loops -fvariable-expansion-in-unroller -fmerge-all-constants -fbranch-target-load-optimize2 -fsched2-use-superblocks -falign-loops=16 -falign-functions=16 -falign-jumps=16 -falign-labels=16"

# Debian 7.7 / Ubuntu 14.04 (gcc 4.7+)
#extracflags="$extracflags -Ofast -flto -fuse-linker-plugin -ftree-loop-if-convert-stores"

CFLAGS="-O3 -march=corei7-avx -msha -Wall" ./configure --with-curl
#CFLAGS="-O3 -march=native -Wall" ./configure --with-curl
#CFLAGS="-O3 -march=native -Wall" CXXFLAGS="$CFLAGS -std=gnu++11" ./configure --with-curl

make -j 4

strip -s cpuminer
