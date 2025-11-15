#!/bin/sh
#
# make clean and rm all the targetted executables.

rm cpuminer-avx10* cpuminer-arrowlake* cpuminer-graniterapids* cpuminer-avx512* cpuminer-alderlake cpuminer-avx10* cpuminer-avx2* cpuminer-avx cpuminer-sse* cpuminer-ssse3 cpuminer-zen* cpuminer-x64 cpuminer-armv* cpuminer-m2 cpuminer-m4 > /dev/null

rm cpuminer-avx512* cpuminer-avx2* cpuminer-avx.exe cpuminer-sse* cpuminer-zen* cpuminer-x64.exe > /dev/null

make distclean > /dev/null
