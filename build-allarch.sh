#!/bin/bash
#
# This script is not intended for users, it is only used for compile testing
# during develpment. However the information contained may provide compilation
# tips to users.

rm cpuminer-avx512-sha-vaes cpuminer-avx512-sha cpuminer-avx512 cpuminer-avx2 cpuminer-avx cpuminer-aes-sse42 cpuminer-sse42 cpuminer-ssse3 cpuminer-sse2 cpuminer-zen cpuminer-zen3  > /dev/null

# Icelake AVX512 SHA VAES
make distclean || echo clean
rm -f config.status
./autogen.sh || echo done
CFLAGS="-O3 -march=icelake-client -Wall -fno-common" ./configure --with-curl
make -j 8
strip -s cpuminer.exe
mv cpuminer.exe cpuminer-avx512-sha-vaes.exe
strip -s cpuminer
mv cpuminer cpuminer-avx512-sha-vaes

# Rocketlake AVX512 SHA AES
make clean || echo clean
rm -f config.status
CFLAGS="-O3 -march=cascadelake -msha -Wall -fno-common" ./configure --with-curl
#CFLAGS="-O3 -march=skylake-avx512 -msha -Wall -fno-common" ./configure --with-curl
# CFLAGS="-O3 -march=rocketlake -Wall -fno-common" ./configure --with-curl
make -j 8
strip -s cpuminer.exe
mv cpuminer.exe cpuminer-avx512-sha.exe
strip -s cpuminer
mv cpuminer cpuminer-avx512-sha

# Slylake-X AVX512 AES
make clean || echo clean
rm -f config.status
CFLAGS="-O3 -march=skylake-avx512 -Wall -fno-common" ./configure --with-curl
make -j 8
strip -s cpuminer.exe
mv cpuminer.exe cpuminer-avx512.exe
strip -s cpuminer
mv cpuminer cpuminer-avx512

# Haswell AVX2 AES
make clean || echo clean
rm -f config.status
# GCC 9 doesn't include AES with core-avx2
CFLAGS="-O3 -march=core-avx2 -maes -Wall -fno-common" ./configure --with-curl
make -j 8
strip -s cpuminer.exe
mv cpuminer.exe cpuminer-avx2.exe
strip -s cpuminer
mv cpuminer cpuminer-avx2

# Sandybridge AVX AES
make clean || echo clean
rm -f config.status
CFLAGS="-O3 -march=corei7-avx -maes -Wall -fno-common" ./configure --with-curl
make -j 8
strip -s cpuminer.exe
mv cpuminer.exe cpuminer-avx.exe
strip -s cpuminer
mv cpuminer cpuminer-avx

# Westmere SSE4.2 AES
make clean || echo clean
rm -f config.status
CFLAGS="-O3 -march=westmere -maes -Wall -fno-common" ./configure --with-curl
make -j 8
strip -s cpuminer.exe
mv cpuminer.exe cpuminer-aes-sse42.exe
strip -s cpuminer
mv cpuminer cpuminer-aes-sse42

# Nehalem SSE4.2
make clean || echo clean
rm -f config.status
CFLAGS="-O3 -march=corei7 -Wall -fno-common" ./configure --with-curl
make -j 8
strip -s cpuminer.exe
mv cpuminer.exe cpuminer-sse42.exe
strip -s cpuminer
mv cpuminer cpuminer-sse42

# Core2 SSSE3
make clean || echo clean
rm -f config.status
CFLAGS="-O3 -march=core2 -Wall -fno-common" ./configure --with-curl
make -j 8
strip -s cpuminer.exe
mv cpuminer.exe cpuminer-ssse3.exe
strip -s cpuminer
mv cpuminer cpuminer-ssse3

# Generic SSE2
make clean || echo clean
rm -f config.status
CFLAGS="-O3 -msse2 -Wall -fno-common" ./configure --with-curl
make -j 8
strip -s cpuminer.exe
mv cpuminer.exe cpuminer-sse2.exe
strip -s cpuminer
mv cpuminer cpuminer-sse2

# AMD Zen1 AVX2 SHA
make clean || echo done
rm -f config.status
CFLAGS="-O3 -march=znver1 -Wall -fno-common" ./configure --with-curl
make -j 8
strip -s cpuminer.exe
mv cpuminer.exe cpuminer-zen.exe
strip -s cpuminer
mv cpuminer cpuminer-zen

# AMD Zen3 AVX2 SHA VAES
make clean || echo done
rm -f config.status
CFLAGS="-O3 -march=znver2 -mvaes -Wall -fno-common" ./configure --with-curl
# CFLAGS="-O3 -march=znver3 -Wall -fno-common" ./configure --with-curl
make -j 8
strip -s cpuminer.exe
mv cpuminer.exe cpuminer-zen3.exe
strip -s cpuminer
mv cpuminer cpuminer-zen3

# Native to current CPU
make clean || echo done
rm -f config.status
CFLAGS="-O3 -march=native -Wall -fno-common" ./configure --with-curl
make -j 8
strip -s cpuminer.exe
strip -s cpuminer

