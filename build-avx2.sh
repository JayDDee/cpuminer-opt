#!/bin/sh

# Linux build

make distclean || echo clean
rm -f config.status
./autogen.sh || echo done
CFLAGS="-O3 -march=haswell -maes -Wall" ./configure --with-curl
make -j $(nproc)
