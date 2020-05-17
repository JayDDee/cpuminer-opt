#!/bin/bash
#
# imake clean and rm all the targetted executables.
# tips to users.

rm cpuminer-avx512-sha-vaes cpuminer-avx512 cpuminer-avx2 cpuminer-avx cpuminer-aes-sse42 cpuminer-sse2 cpuminer-zen  > /dev/null

rm cpuminer-avx512-sha-vaes.exe cpuminer-avx512.exe cpuminer-avx2.exe cpuminer-avx.exe cpuminer-aes-sse42.exe cpuminer-sse2.exe cpuminer-zen.exe  > /dev/null

make distclean > /dev/null
