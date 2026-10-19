#!/bin/bash

# Native aarch64 build.
#
# To cross compile from another architecture instead, set CROSS to the
# toolchain prefix:
#
#   CROSS=aarch64-linux-gnu ./build-armv8.sh
#
# +crypto+sha2+aes requires the ARMv8 crypto extension; drop it on a board
# without one. See armbuild-all.sh for other targets (armv8.2, armv9, Apple).

make distclean || echo clean
rm -f config.status
./autogen.sh || echo done

CFLAGS="-O2 -march=armv8-a+crypto+sha2+aes -Wall -flax-vector-conversions" \
  ./configure --with-curl ${CROSS:+--host=$CROSS --build=$(./config.guess)}

make -j $(nproc)

strip -s cpuminer
