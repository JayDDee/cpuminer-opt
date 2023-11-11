#!/bin/bash
#
# This script is not intended for users, it is only used for compile testing
# during develpment. However the information contained may provide compilation
# tips to users.

rm cpuminer cpuminer-armv8 cpuminer-armv8-aes cpuminer-armv8-sha2 cpuminer-armv8-aes-sha2 cpuminer-avx512-sha-vaes cpuminer-avx512 cpuminer-avx2-sha cpuminer-avx2-sha-vaes cpuminer-avx2 cpuminer-avx cpuminer-aes-sse42 cpuminer-sse42 cpuminer-ssse3 cpuminer-sse2 cpuminer-zen cpuminer-zen3 cpuminer-zen4 cpuminer-alderlake cpuminer-x64 > /dev/null

make distclean || echo clean
rm -f config.status
./autogen.sh || echo done
CFLAGS="-O3 -march=armv8-a+crypto+sha2+aes -Wall -flax-vector-conversions" ./configure  --with-curl 
make -j $nproc
strip -s cpuminer
mv cpuminer cpuminer-armv8-aes-sha2

make clean || echo clean
rm -f config.status
CFLAGS="-O3 -march=armv8-a+crypto+sha2 -Wall -flax-vector-conversions" ./configure  --with-curl      
make -j $nproc
strip -s cpuminer
mv cpuminer cpuminer-armv8-sha2

make clean || echo clean
rm -f config.status
CFLAGS="-O3 -march=armv8-a+crypto+aes -Wall -flax-vector-conversions" ./configure  --with-curl      
make -j $nproc
strip -s cpuminer
mv cpuminer cpuminer-armv8-aes

make clean || echo clean
rm -f config.status
CFLAGS="-O3 -march=armv8-a -Wall -flax-vector-conversions" ./configure  --with-curl
make -j $nproc
strip -s cpuminer
mv cpuminer cpuminer-armv8

make clean || echo clean
rm -f config.status
CFLAGS="-O3 -march=native -Wall -flax-vector-conversions" ./configure  --with-curl     
make -j $nproc
strip -s cpuminer
