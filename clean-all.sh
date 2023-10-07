#!/bin/bash
#
# make clean and rm all the targetted executables.

rm cpuminer-avx512-sha-vaes cpuminer-avx512 cpuminer-avx2 cpuminer-avx cpuminer-aes-sse42 cpuminer-sse2 cpuminer-avx2-sha cpuminer-sse42 cpuminer-ssse3 cpuminer-avx2-sha-vaes cpuminer-zen3 cpuminer-zen4 cpuminer-x64 > /dev/null

rm cpuminer-avx512-sha-vaes.exe cpuminer-avx512-sha.exe cpuminer-avx512.exe cpuminer-avx2.exe cpuminer-avx.exe cpuminer-aes-sse42.exe cpuminer-sse2.exe cpuminer-avx2-sha.exe cpuminer-sse42.exe cpuminer-ssse3.exe cpuminer-avx2-sha-vaes.exe cpuminer-zen3.exe cpuminer-zen4.exe cpuminer-x64.exe > /dev/null

make distclean > /dev/null
