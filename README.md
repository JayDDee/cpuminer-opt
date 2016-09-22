This project is forked by Jay D Dee.

Updated for v3.3.2 Windows support.

Building on linux prerequisites:

It is assumed users know how to install packages on their system and
be able to compile standard source packages. This is basic Linux and
beyond the scope of cpuminer-opt. 

Make sure you have the basic development packages installed.
Here is a good start:

http://askubuntu.com/questions/457526/how-to-install-cpuminer-in-ubuntu

Install any additional dependencies needed by cpuminer-opt. The list below
are some of the ones that may not be in the default install and need to
be installed manually. There may be others, read the error messages they
will give a clue as to the missing package.

The folliwing command should install everything you need on Debian based
packages:

sudo apt-get install build-essential libssl-dev libcurl4-openssl-dev libjansson-dev libgmp-dev automake

Building on Linux, see below for Windows.

Dependencies

build-essential  (for Ubuntu, Development Tools package group on Fedora)
automake
libjansson-dev
libgmp-dev
libcurl4-openssl-dev
libssl-dev
pthreads
zlib

tar xvzf [file.tar.gz]
cd [file]

Run build.sh to build on Linux or execute the following commands.

./autogen.sh
CFLAGS="-O3 -march=native -Wall" CXXFLAGS="$CFLAGS -std=gnu++11" ./configure --with-curl
make

Start mining.

./cpuminer -a algo ...

Building on Windows prerequisites:

msys
mingw_w64
Visual C++ redistributable 2008 X64
openssl, not sure about this

Install msys and mingw_w64, only needed once.

Unpack msys into C:\msys or your preferred directory.

Install mingw__w64 from win-builds.
Follow instructions, check "msys or cygwin" and "x86_64" and accept default
existing msys instalation.

Open a msys shell by double clicking on msys.bat.
Note that msys shell uses linux syntax for file specifications, "C:\" is
mounted at "/c/".

Add mingw bin directory to PATH variable
PATH="/c/msys/opt/windows_64/bin/:$PATH"

Instalation complete, compile cpuminer-opt

Unpack cpuminer-opt source files using tar from msys shell, or using 7zip
or similar Windows program.

In msys shell cd to miner directory.
cd /c/path/to/cpuminer-opt

Run winbuild.sh to build on Windows or execute the following commands.

./autogen.sh
CFLAGS="-O3 -march=native -Wall" CXXFLAGS="$CFLAGS -std=gnu++11 -fpermissive" ./configure --with-curl
make

The following tips may be useful for older AMD CPUs.

Some users with AMD CPUs without AES_NI have reported problems compiling
with build.sh or "-march=native". Problems have included compile errors
and poor performance. These users are recommended to compile manually
specifying "-march=btver1" on the configure command line.

Support for even older x86_64 without AES_NI or SSE2 is not availble.
cpuminer-multi by TPruvot supports this architecture.

The rest of this file is taken from cpuminer-multi.

----------------


CPUMiner-Multi
==============

[![Build Status](https://travis-ci.org/tpruvot/cpuminer-multi.svg)](https://travis-ci.org/tpruvot/cpuminer-multi)

This is a multi-threaded CPU miner,
fork of [pooler](//github.com/pooler)'s cpuminer (see AUTHORS for list of contributors).

#### Table of contents

* [Algorithms](#algorithms)
* [Dependencies](#dependencies)
* [Download](#download)
* [Build](#build)
* [Usage instructions](#usage-instructions)
* [Donations](#donations)
* [Credits](#credits)
* [License](#license)

Algorithms
==========
#### Currently supported
 * ✓ __scrypt__ (Litecoin, Dogecoin, Feathercoin, ...)
 * ✓ __scrypt:N__
 * ✓ __sha256d__ (Bitcoin, Freicoin, Peercoin/PPCoin, Terracoin, ...)
 * ✓ __axiom__ (Axiom Shabal-256 based MemoHash)
 * ✓ __blake__ (Saffron [SFR] Blake-256)
 * ✓ __bmw__ (Midnight [MDT] BMW-256)
 * ✓ __cryptonight__ (Bytecoin [BCN], Monero)
 * ✓ __cryptonight-light__ (Aeon)
 * ✓ __dmd-gr__ (Diamond-Groestl)
 * ✓ __fresh__ (FreshCoin)
 * ✓ __groestl__ (Groestlcoin)
 * ✓ __lyra2RE__ (Lyrabar, Cryptocoin)
 * ✓ __lyra2REv2__ (VertCoin [VTC])
 * ✓ __myr-gr__ (Myriad-Groestl)
 * ✓ __neoscrypt__ (Feathercoin)
 * ✓ __nist5__ (MistCoin [MIC], TalkCoin [TAC], ...)
 * ✓ __pentablake__ (Joincoin)
 * ✓ __pluck__ (Supcoin [SUP])
 * ✓ __quark__ (Quarkcoin)
 * ✓ __qubit__ (MyriadCoin [MYR])
 * ✓ __skein__ (Skeincoin, Myriadcoin, Xedoscoin, ...)
 * ✓ __skein2__ (Woodcoin)
 * ✓ __s3__ (OneCoin)
 * ✓ __x11__ (Darkcoin [DRK], Hirocoin, Limecoin, ...)
 * ✓ __x13__ (Sherlockcoin, [ACE], [B2B], [GRC], [XHC], ...)
 * ✓ __x14__ (X14, Webcoin [WEB])
 * ✓ __x15__ (RadianceCoin [RCE])
 * ✓ __zr5__ (Ziftrcoin [ZRC])

#### Implemented, but untested
 * ? blake2s
 * ? hefty1 (Heavycoin)
 * ? keccak (Maxcoin  HelixCoin, CryptoMeth, Galleon, 365coin, Slothcoin, BitcointalkCoin)
 * ? luffa (Joincoin, Doomcoin)
 * ? shavite3 (INKcoin)
 * ? sib X11 + gost (SibCoin)

#### Planned support for
 * *scrypt-jane* (YaCoin, CopperBars, Pennies, Tickets, etc..)
 
Dependencies
============
 * libcurl http://curl.haxx.se/libcurl/
 * jansson http://www.digip.org/jansson/ (jansson source is included in-tree)
 * openssl libcrypto https://www.openssl.org/
 * pthreads
 * zlib (for curl/ssl)

Download
========
 * Windows releases: https://github.com/tpruvot/cpuminer-multi/releases
 * Git tree:   https://github.com/tpruvot/cpuminer-multi
   * Clone with `git clone https://github.com/tpruvot/cpuminer-multi`

Build
=====

#### Basic *nix build instructions:
 * just use ./build.sh
_OR_
 * ./autogen.sh	# only needed if building from git repo
 * ./nomacro.pl	# only needed if building on Mac OS X or with Clang
 * ./configure CFLAGS="-O3 -march=native" --with-crypto --with-curl
   * # Use -march=native if building for a single machine
 * make

#### Notes for AIX users:
 * To build a 64-bit binary, export OBJECT_MODE=64
 * GNU-style long options are not supported, but are accessible via configuration file

#### Basic Windows build with Visual Studio 2013
 * All the required .lib files are now included in tree (windows only)
 * AVX enabled by default for x64 platform (AVX2 and XOP could also be used)

#### Basic Windows build instructions, using MinGW64:
 * Install MinGW64 and the MSYS Developer Tool Kit (http://www.mingw.org/)
   * Make sure you have mstcpip.h in MinGW\include
 * install pthreads-w64
 * Install libcurl devel (http://curl.haxx.se/download.html)
   * Make sure you have libcurl.m4 in MinGW\share\aclocal
   * Make sure you have curl-config in MinGW\bin
 * Install openssl devel (https://www.openssl.org/related/binaries.html)
 * In the MSYS shell, run:
   * for 64bit, you can use ./mingw64.sh else :
     ./autogen.sh	# only needed if building from git repo
   * LIBCURL="-lcurldll" ./configure CFLAGS="*-march=native*"
     * # Use -march=native if building for a single machine
   * make

#### Architecture-specific notes:
 * ARM:
   * No runtime CPU detection. The miner can take advantage of some instructions specific to ARMv5E and later processors, but the decision whether to use them is made at compile time, based on compiler-defined macros.
   * To use NEON instructions, add "-mfpu=neon" to CFLAGS.
 * x86:
   * The miner checks for SSE2 instructions support at runtime, and uses them if they are available.
 * x86-64:	
   * The miner can take advantage of AVX, AVX2 and XOP instructions, but only if both the CPU and the operating system support them.
     * Linux supports AVX starting from kernel version 2.6.30.
     * FreeBSD supports AVX starting with 9.1-RELEASE.
     * Mac OS X added AVX support in the 10.6.8 update.
     * Windows supports AVX starting from Windows 7 SP1 and Windows Server 2008 R2 SP1.
   * The configure script outputs a warning if the assembler doesn't support some instruction sets. In that case, the miner can still be built, but unavailable optimizations are left off.

Usage instructions
==================
Run "cpuminer --help" to see options.

### Connecting through a proxy

Use the --proxy option.

To use a SOCKS proxy, add a socks4:// or socks5:// prefix to the proxy host  
Protocols socks4a and socks5h, allowing remote name resolving, are also available since libcurl 7.18.0.

If no protocol is specified, the proxy is assumed to be a HTTP proxy.  
When the --proxy option is not used, the program honors the http_proxy and all_proxy environment variables.

Donations
=========
Donations for the work done in this fork are accepted :

Tanguy Pruvot :
* BTC: `1FhDPLPpw18X4srecguG3MxJYe4a1JsZnd`
* ZRC: `ZX6LmrCwphNgitxvDnf8TX6Tsegfxpeozx`

Lucas Jones :
* MRO: `472haywQKoxFzf7asaQ4XKBc2foAY4ezk8HiN63ifW4iAbJiLnfmJfhHSR9XmVKw2WYPnszJV9MEHj9Z5WMK9VCNHaGLDmJ`
* BTC: `139QWoktddChHsZMWZFxmBva4FM96X2dhE`

Credits
=======
CPUMiner-multi was forked from pooler's CPUMiner, and has been started by Lucas Jones.
* [tpruvot](https://github.com/tpruvot) added all the recent features and newer algorythmns
* [Wolf9466](https://github.com/wolf9466) helped with Intel AES-NI support for CryptoNight

License
=======
GPLv2.  See COPYING for details.
