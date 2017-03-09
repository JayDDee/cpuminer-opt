#!/bin/bash

make distclean || echo clean
rm -f config.status
./autogen.sh || echo done
CFLAGS="-O3 -march=core-avx2 -Wall" CXXFLAGS="$CFLAGS -std=gnu++11 -fpermissive" ./configure --with-curl
make -j 4
strip -s cpuminer.exe
mv cpuminer.exe cpuminer-aes-avx2.exe

make clean || echo clean
rm -f config.status
./autogen.sh || echo done
CFLAGS="-O3 -march=corei7-avx -Wall" CXXFLAGS="$CFLAGS -std=gnu++11 -fpermissive" ./configure --with-curl
make -j 4
strip -s cpuminer.exe
mv cpuminer.exe cpuminer-aes-avx.exe

make clean || echo clean
rm -f config.status
./autogen.sh || echo done
CFLAGS="-O3 -maes -msse4.2 -Wall" CXXFLAGS="$CFLAGS -std=gnu++11 -fpermissive" ./configure --with-curl
make -j 4
strip -s cpuminer.exe
mv cpuminer.exe cpuminer-aes-sse42.exe

make clean || echo clean
rm -f config.status
./autogen.sh || echo done
CFLAGS="-O3 -march=corei7 -Wall" CXXFLAGS="$CFLAGS -std=gnu++11 -fpermissive" ./configure --with-curl
make -j 4
strip -s cpuminer.exe
mv cpuminer.exe cpuminer-sse42.exe

make clean || echo clean
rm -f config.status
./autogen.sh || echo done
CFLAGS="-O3 -march=core2 -Wall" CXXFLAGS="$CFLAGS -std=gnu++11 -fpermissive" ./configure --with-curl
make -j 4
strip -s cpuminer.exe
mv cpuminer.exe cpuminer-sse2.exe

make clean || echo done


