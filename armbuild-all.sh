#!/bin/bash
#
# This script is not intended for users, it is only used for compile testing
# during development. However, the information contained may provide compilation
# tips to users.

rm cpuminer cpuminer-m2 cpuminer-m4 cpuminer-armv9-crypto-sha3 cpuminer-armv9-crypto cpuminer-armv9 cpuminer-armv8.5-crypto-sha3-sve2 cpuminer-armv8.4-crypto-sha3 cpuminer-armv8 cpuminer-armv8-crypto > /dev/null

# armv9 needs gcc-13
# -march-armv9-a includes SVE2 but no crypto
# -march=armv9-a+crypto adds AES & SHA256 but not SHA512

make distclean || echo clean
rm -f config.status
./autogen.sh || echo done
CFLAGS="-O3 -march=armv9-a+crypto+sha3 -Wall -flax-vector-conversions" ./configure  --with-curl
make -j $(nproc)
mv cpuminer cpuminer-armv9-crypto-sha3

make clean || echo clean
CFLAGS="-O3 -march=armv9-a+crypto -Wall -flax-vector-conversions" ./configure  --with-curl
make -j $(nproc)
mv cpuminer cpuminer-armv9-crypto

make clean || echo clean
CFLAGS="-O3 -march=armv9-a -Wall -flax-vector-conversions" ./configure  --with-curl
make -j $(nproc)
mv cpuminer cpuminer-armv9

# Apple M4: armv9.2, AES, SHA3, SVE2
make clean || echo clean
CFLAGS="-O3 -march=armv9.2-a+crypto+sha3 -Wall -flax-vector-conversions" ./configure  --with-curl
make -j $(nproc)
mv cpuminer cpuminer-m4

# Apple M2: armv8.6, AES, SHA3
make clean || echo clean
CFLAGS="-O3 -march=armv8.6-a+crypto+sha3 -Wall -flax-vector-conversions" ./configure  --with-curl
make -j $(nproc)
mv cpuminer cpuminer-m2

# SVE2 available in armv8.5
make clean || echo clean
CFLAGS="-O3 -march=armv8.5-a+crypto+sha3+sve2 -Wall -flax-vector-conversions" ./configure  --with-curl
make -j $(nproc)
mv cpuminer cpuminer-armv8.5-crypto-sha3-sve2

# Apple M1: armv8.4 AES, SHA3
make clean || echo clean
CFLAGS="-O3 -march=armv8.4-a+crypto+sha3 -Wall -flax-vector-conversions" ./configure  --with-curl
make -j $(nproc)
mv cpuminer cpuminer-armv8.4-crypto-sha3

# Cortex-A76 (Orange Pi 5)
make clean || echo clean
rm -f config.status
CFLAGS="-O3 -march=armv8.2-a+crypto -Wall -flax-vector-conversions" ./configure  --with-curl
make -j $(nproc)
mv cpuminer cpuminer-armv8-crypto

make clean || echo clean
rm -f config.status
CFLAGS="-O3 -march=armv8-a+crypto -Wall -flax-vector-conversions" ./configure  --with-curl
make -j $(nproc)
mv cpuminer cpuminer-armv8-crypto

make clean || echo clean
rm -f config.status
CFLAGS="-O3 -march=armv8-a -Wall -flax-vector-conversions" ./configure  --with-curl
make -j $(nproc)
mv cpuminer cpuminer-armv8

make clean || echo clean
rm -f config.status
CFLAGS="-O3 -march=native -Wall -flax-vector-conversions" ./configure  --with-curl     
make -j $(nproc)
