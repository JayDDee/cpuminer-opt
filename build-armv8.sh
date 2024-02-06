#!/bin/bash

# Linux build

make distclean || echo clean

rm -f config.status
./autogen.sh || echo done

CFLAGS="-O2 -march=armv8-a+crypto+sha2+aes -Wall -flax-vector-conversions" ./configure  --with-curl  --host=aarch64-cortexa76-elf --build=x86_64-pc-linux-gnu --target=aarch64-cortexa76-elf
#CFLAGS="-O2 -march=armv8-a+crypto+sha2+aes -Wall -flax-vector-conversions" ./configure  --with-curl

make -j $(nproc)

strip -s cpuminer
