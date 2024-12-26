#!/bin/bash
#
# This script is not intended for users, it is only used for compile testing
# during develpment. However the information contained may provide compilation
# tips to users.

rm cpuminer cpuminer-armv9-crypto-sha3 cpuminer-armv9-crypto cpuminer-armv9 cpuminer-armv8.5-crypto-sha3-sve2 cpuminer-armv8.4-crypto-sha3 cpuminer-armv8 cpuminer-armv8-crypto cpuminer-avx512-sha-vaes cpuminer-avx512 cpuminer-avx2-sha cpuminer-avx2-sha-vaes cpuminer-avx2 cpuminer-avx cpuminer-aes-sse42 cpuminer-sse42 cpuminer-ssse3 cpuminer-sse2 cpuminer-zen cpuminer-zen3 cpuminer-zen4 cpuminer-alderlake cpuminer-x64 > /dev/null

# armv9 needs gcc-13
# -march-armv9-a includes SVE2 but no crypto
# -march=armv9-a+crypto adds AES & SHA2 but not SHA512

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

# SVE2 available in armv8.5
make clean || echo clean
CFLAGS="-O3 -march=armv8.5-a+crypto+sha3+sve2 -Wall -flax-vector-conversions" ./configure  --with-curl
make -j $(nproc)
mv cpuminer cpuminer-armv8.5-crypto-sha3-sve2

# SHA3 available in armv8.4
make clean || echo clean
CFLAGS="-O3 -march=armv8.4-a+crypto+sha3 -Wall -flax-vector-conversions" ./configure  --with-curl
make -j $(nproc)
mv cpuminer cpuminer-armv8.4-crypto-sha3

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
