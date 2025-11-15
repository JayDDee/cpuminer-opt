#!/bin/bash
#
# This script is not intended for users, it is only used for compile testing
# during develpment. However the information contained may provide compilation
# tips to users.

./clean-all.sh

# AVX512 SHA VAES: Intel Core Icelake, Rocketlake
make distclean || echo clean
rm -f config.status
./autogen.sh || echo done
#CFLAGS="-O3 -march=icelake-client -Wall" ./configure --with-curl
# Rocketlake needs gcc-11
CFLAGS="-O3 -march=rocketlake -Wall" ./configure --with-curl
make -j $(nproc)
strip -s cpuminer
mv cpuminer cpuminer-avx512-sha-vaes

# Intel Core Alderlake: AVX2 SHA VAES, needs gcc-12
make clean || echo clean
rm -f config.status
CFLAGS="-O3 -march=alderlake -Wall" ./configure --with-curl
make -j $(nproc)
strip -s cpuminer
mv cpuminer cpuminer-alderlake

# Intel Core Arrowlake-s: AVX2 SHA512 VAES, needs gcc-14
# Arrowlake-s includes SHA512, Arrowlake does not?
make clean || echo clean
rm -f config.status
CFLAGS="-O3 -march=arrowlake-s -Wall" ./configure --with-curl
make -j $(nproc)
strip -s cpuminer
mv cpuminer cpuminer-arrowlake-s

# Intel Core Graniterapids: AVX512, SHA256, VAES, AMX, needs gcc-14
make clean || echo clean
rm -f config.status
CFLAGS="-O3 -march=graniterapids -Wall" ./configure --with-curl
make -j $(nproc)
strip -s cpuminer
mv cpuminer cpuminer-graniterapids

# Graniterapids + SHA512, AVX10.1
make clean || echo clean
rm -f config.status
CFLAGS="-O3 -march=graniterapids -msha512 -mavx10.1 -Wall" ./configure --with-curl
make -j $(nproc)
strip -s cpuminer
mv cpuminer cpuminer-avx10.1

# SHA512 AVX10.2
#make clean || echo clean
#rm -f config.status
#CFLAGS="-O3 -march=graniterapids -msha512 -mavx10.2 -Wall" ./configure --with-curl
#make -j $(nproc)
#strip -s cpuminer
#mv cpuminer cpuminer-avx10_2

# Diamondrapids: AVX10.2, SHA512, APX; needs GCC-15 & CPU with APX to compile.
#make clean || echo clean
#rm -f config.status
#CFLAGS="-O3 -march=diamondrapids -Wall" ./configure --with-curl
#make -j $(nproc)
#strip -s cpuminer
#mv cpuminer cpuminer-diamondrapids

# Zen5: AVX512 SHA VAES, requires gcc-14.
make clean || echo clean
rm -f config.status
CFLAGS="-O3 -march=znver5 -Wall" ./configure --with-curl
# zen4 is close enough for older compiler
#CFLAGS="-O3 -march=znver4 -Wall" ./configure --with-curl

make -j $(nproc)
strip -s cpuminer
mv cpuminer cpuminer-zen5

# Zen4: AVX512 SHA VAES
make clean || echo clean
rm -f config.status
# Zen4: AVX512, SHA, VAES, needs gcc-12.3.
CFLAGS="-O3 -march=znver4 -Wall" ./configure --with-curl
# Inclomplete list of Zen4 AVX512 extensions but includes all extensions used by cpuminer.
#CFLAGS="-O3 -march=znver3 -mavx512f -mavx512cd -mavx512dq -mavx512bw -mavx512vl -mavx512vbmi -mavx512vbmi2 -mavx512bitalg -mavx512vpopcntdq -Wall" ./configure --with-curl
make -j $(nproc)
strip -s cpuminer
mv cpuminer cpuminer-zen4

# Zen3 AVX2 SHA VAES
make clean || echo clean
rm -f config.status
CFLAGS="-O3 -march=znver3 -fno-common " ./configure --with-curl
make -j $(nproc)
strip -s cpuminer
mv cpuminer cpuminer-zen3

# AVX512 AES: Intel Core HEDT Sylake-X, Cascadelake
make clean || echo clean
rm -f config.status
CFLAGS="-O3 -march=skylake-avx512 -maes -Wall" ./configure --with-curl
make -j $(nproc)
strip -s cpuminer
mv cpuminer cpuminer-avx512

# AVX2 SHA VAES: generic, zen3, alderlake...arrowlake
make clean || echo done
rm -f config.status
# vaes doesn't include aes
CFLAGS="-O3 -maes -mavx2 -msha -mvaes -Wall" ./configure --with-curl
make -j $(nproc)
strip -s cpuminer
mv cpuminer cpuminer-avx2-sha-vaes

# AVX2 SHA AES: AMD Zen1
make clean || echo done
rm -f config.status
CFLAGS="-O3 -march=znver1 -maes -Wall" ./configure --with-curl
#CFLAGS="-O3 -maes -mavx2 -msha -Wall" ./configure --with-curl
make -j $(nproc)
strip -s cpuminer
mv cpuminer cpuminer-avx2-sha

# AVX2 AES: Intel Haswell..Cometlake
make clean || echo clean
rm -f config.status
# GCC 9 doesn't include AES with core-avx2
CFLAGS="-O3 -march=core-avx2 -maes -Wall" ./configure --with-curl
make -j $(nproc)
strip -s cpuminer
mv cpuminer cpuminer-avx2

# AVX AES: Intel Sandybridge, Ivybridge
make clean || echo clean
rm -f config.status
CFLAGS="-O3 -march=corei7-avx -maes -Wall" ./configure --with-curl
make -j $(nproc)
strip -s cpuminer
mv cpuminer cpuminer-avx

# SSE4.2 AES SHA: Intel Atom Goldmont, newer Pentium & Celeron
make clean || echo clean
rm -f config.status
CFLAGS="-O3 -march=goldmont -Wall" ./configure --with-curl
make -j $(nproc)
strip -s cpuminer
mv cpuminer cpuminer-sse42-aes-sha

# SSE4.2 AES: Intel Westmere, older Pentium & Celeron
make clean || echo clean
rm -f config.status
CFLAGS="-O3 -march=westmere -maes -Wall" ./configure --with-curl
make -j $(nproc)
strip -s cpuminer
mv cpuminer cpuminer-sse42-aes

# SSE4.2: Intel Nehalem
make clean || echo clean
rm -f config.status
CFLAGS="-O3 -march=corei7 -Wall" ./configure --with-curl
make -j $(nproc)
strip -s cpuminer
mv cpuminer cpuminer-sse42

# SSSE3: Intel Core2
make clean || echo clean
rm -f config.status
CFLAGS="-O3 -march=core2 -Wall" ./configure --with-curl
make -j $(nproc)
strip -s cpuminer
mv cpuminer cpuminer-ssse3

# SSE2
make clean || echo clean
rm -f config.status
CFLAGS="-O3 -march=x86-64 -msse2 -Wall" ./configure --with-curl
make -j $(nproc)
strip -s cpuminer
mv cpuminer cpuminer-sse2

# X86_64
make clean || echo clean
rm -f config.status
CFLAGS="-O3 -march=x86-64 -Wall" ./configure --with-curl
make -j $(nproc)
strip -s cpuminer
mv cpuminer cpuminer-x64

# Native to host CPU
make clean || echo done
rm -f config.status
CFLAGS="-O3 -march=native -Wall" ./configure --with-curl
make -j $(nproc)
strip -s cpuminer

