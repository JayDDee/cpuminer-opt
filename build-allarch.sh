#!/bin/bash
#
# This script is not intended for users, it is only used for compile testing
# during develpment. However the information contained may provide compilation
# tips to users.

rm cpuminer-avx512-sha-vaes cpuminer-avx512 cpuminer-avx2 cpuminer-avx cpuminer-aes-sse42 cpuminer-sse42 cpuminer-ssse3 cpuminer-sse2 cpuminer-zen cpuminer-zen3 cpuminer-zen4 > /dev/null

# AVX512 SHA VAES: Intel Core Icelake, Rocketlake
make distclean || echo clean
rm -f config.status
./autogen.sh || echo done
CFLAGS="-O3 -march=icelake-client -Wall -fno-common" ./configure --with-curl
# Rocketlake needs gcc-11
#CFLAGS="-O3 -march=rocketlake -Wall -fno-common" ./configure --with-curl
make -j 8
strip -s cpuminer
mv cpuminer cpuminer-avx512-sha-vaes

# Zen4 AVX512 SHA VAES
make clean || echo clean
rm -f config.status
# znver3 needs gcc-11, znver4 ?
#CFLAGS="-O3 -march=znver4 -Wall -fno-common " ./configure --with-curl
#CFLAGS="-O3 -march=znver3 -mavx512f -mavx512dq -mavx512bw -mavx512vl -Wall -fno-common " ./configure --with-curl
CFLAGS="-O3 -march=znver2 -mvaes -mavx512f -mavx512dq -mavx512bw -mavx512vl -Wall -fno-common " ./configure --with-curl
make -j 8
strip -s cpuminer
mv cpuminer cpuminer-zen4

# Zen3 AVX2 SHA VAES
make clean || echo clean
rm -f config.status
CFLAGS="-O3 -march=znver2 -mvaes -fno-common " ./configure --with-curl
#CFLAGS="-O3 -march=znver3 -fno-common " ./configure --with-curl
make -j 8
strip -s cpuminer
mv cpuminer cpuminer-zen3

# AVX512 AES: Intel Core HEDT Sylake-X, Cascadelake
make clean || echo clean
rm -f config.status
CFLAGS="-O3 -march=skylake-avx512 -maes -Wall -fno-common" ./configure --with-curl
make -j 8
strip -s cpuminer
mv cpuminer cpuminer-avx512

# AVX2 SHA VAES: Intel Alderlake, AMD Zen3
make clean || echo done
rm -f config.status
# vaes doesn't include aes
CFLAGS="-O3 -maes -mavx2 -msha -mvaes -Wall -fno-common" ./configure --with-curl
make -j 8
strip -s cpuminer
mv cpuminer cpuminer-avx2-sha-vaes

# AVX2 SHA AES: AMD Zen1
make clean || echo done
rm -f config.status
#CFLAGS="-O3 -march=znver1 -maes -Wall -fno-common" ./configure --with-curl
CFLAGS="-O3 -maes -mavx2 -msha -Wall -fno-common" ./configure --with-curl
make -j 8
strip -s cpuminer
mv cpuminer cpuminer-avx2-sha

# AVX2 AES: Intel Haswell..Cometlake
make clean || echo clean
rm -f config.status
# GCC 9 doesn't include AES with core-avx2
CFLAGS="-O3 -march=core-avx2 -maes -Wall -fno-common" ./configure --with-curl
make -j 8
strip -s cpuminer
mv cpuminer cpuminer-avx2

# AVX AES: Intel Sandybridge, Ivybridge
make clean || echo clean
rm -f config.status
CFLAGS="-O3 -march=corei7-avx -maes -Wall -fno-common" ./configure --with-curl
make -j 8
strip -s cpuminer
mv cpuminer cpuminer-avx

# SSE4.2 AES: Intel Westmere
make clean || echo clean
rm -f config.status
CFLAGS="-O3 -march=westmere -maes -Wall -fno-common" ./configure --with-curl
make -j 8
strip -s cpuminer
mv cpuminer cpuminer-aes-sse42

# SSE4.2: Intel Nehalem
make clean || echo clean
rm -f config.status
CFLAGS="-O3 -march=corei7 -Wall -fno-common" ./configure --with-curl
make -j 8
strip -s cpuminer
mv cpuminer cpuminer-sse42

# SSSE3: Intel Core2
make clean || echo clean
rm -f config.status
CFLAGS="-O3 -march=core2 -Wall -fno-common" ./configure --with-curl
make -j 8
strip -s cpuminer
mv cpuminer cpuminer-ssse3

# SSE2
make clean || echo clean
rm -f config.status
CFLAGS="-O3 -msse2 -Wall -fno-common" ./configure --with-curl
make -j 8
strip -s cpuminer
mv cpuminer cpuminer-sse2

# Native to host CPU
make clean || echo done
rm -f config.status
CFLAGS="-O3 -march=native -Wall -fno-common" ./configure --with-curl
make -j 8
strip -s cpuminer

