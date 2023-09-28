#!/bin/bash
#
# Compile on Windows using MSYS2 and MinGW.

make distclean || echo clean
rm -f config.status
./autogen.sh || echo done
CFLAGS="-O3 -march=native -Wall -D_WIN32_WINNT=0x0601" ./configure --with-curl
make -j 4
strip -s cpuminer
