#!/bin/sh

make distclean || echo clean
rm -f config.status
./autogen.sh || echo done
CFLAGS="-O3 -march=native -Wall" ./configure --with-curl
make -j $(nproc)

#strip -s cpuminer
