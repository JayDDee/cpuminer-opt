This file is included in the Windows binary package. Compile instructions
for Linux and Windows can be found in RELEASE_NOTES.

This package is officially avalable only from:
 https://github.com/JayDDee/cpuminer-opt
No other sources should be trusted.

cpuminer is a console program that is executed from a DOS or Powershell
prompt. There is no GUI and no mouse support.

Miner programs are often flagged as malware by antivirus programs. This is
a false positive, they are flagged simply because they are cryptocurrency 
miners. The source code is open for anyone to inspect. If you don't trust
the software, don't use it.

Choose the exe that best matches you CPU's features or use trial and
error to find the fastest one that doesn't crash. Pay attention to
the features listed at cpuminer startup to ensure you are mining at
optimum speed using the best available features.

Architecture names and compile options used are only provided for Intel
Core series. Budget CPUs like Pentium and Celeron are often missing some
features.

AMD CPUs older than Piledriver, including Athlon x2 and Phenom II x4, are not
supported by cpuminer-opt due to an incompatible implementation of SSE2 on
these CPUs. Some algos may crash the miner with an invalid instruction.
Users are recommended to use an unoptimized miner such as cpuminer-multi.

More information for Intel and AMD CPU architectures and their features
can be found on Wikipedia.

https://en.wikipedia.org/wiki/List_of_Intel_CPU_microarchitectures

https://en.wikipedia.org/wiki/List_of_AMD_CPU_microarchitectures


Exe file name                Compile flags            Arch name

cpuminer-sse2.exe            "-msse2"                 Core2, Nehalem   
cpuminer-aes-sse42.exe       "-marxh=westmere"        Westmere
cpuminer-avx.exe             "-march=corei7-avx"      Sandybridge, Ivybridge
cpuminer-avx2.exe            "-march=core-avx2 -maes" Haswell(1)
cpuminer-avx512.exe          "-march=skylake-avx512"  Skylake-X, Cascadelake-X
cpuminer-zen.exe             "-march=znver1"          Zen1, Zen2
cpuminer-zen3.exe            "-march=znver2 -mvaes"   Zen3(2) 
cpuminer-avx512-sha-vaes.exe "-march=icelake-client"  Icelake(3)

(1) Haswell includes Broadwell, Skylake, Kabylake, Coffeelake & Cometlake. 
(2) Zen3 build uses Zen2+VAES as workaround until Zen3 compiler support is
    available. Zen2 CPUs should use Zen build.
(3) Icelake is only available on some laptops. Mining with a laptop is not
recommended.

Notes about included DLL files:

Downloading DLL files from alternative sources presents an inherent
security risk if their source is unknown. All DLL files included have
been copied from the Ubuntu-20.04 instalation or compiled by me from
source code obtained from the author's official repository. The exact
procedure is documented in the build instructions for Windows:
https://github.com/JayDDee/cpuminer-opt/wiki/Compiling-from-source

If you like this software feel free to donate:

BTC: 12tdvfF7KmAsihBXQXynT6E6th2c2pByTT


