This file is included in the Windows binary package. Compile instructions
for Linux and Windows can be found in RELEASE_NOTES.

cpuminer-opt is open source and free of any fees. Many forks exist that are
closed source and contain usage fees. support open source free software.

This package is officially avalaible only from:

 https://github.com/JayDDee/cpuminer-opt

No other sources should be trusted.

cpuminer is a console program that is executed from a DOS or Powershell
command prompt. There is no GUI and no mouse support.

New users are encouraged to consult the cpuminer-opt Wiki for detailed
information on usage:

https://github.com/JayDDee/cpuminer-opt/wiki

Miner programs are often flagged as malware by antivirus programs. This is
a false positive, they are flagged simply because they are cryptocurrency 
miners. The source code is open for anyone to inspect. If you don't trust
the software, don't use it.

Choose the exe that best matches you CPU's features or use trial and
error to find the fastest one that works. Pay attention to
the features listed at cpuminer startup to ensure you are mining at
optimum speed using the best available features.

Architecture names and compile options used are only provided for 
mainstream desktop CPUs. Budget CPUs like Pentium and Celeron are often
missing some features. Check your CPU.

Support for AMD CPUs older than Ryzen is incomplete and without specific 
recommendations. Find the best fit. CPUs older than Piledriver, including
Athlon x2 and Phenom II x4, are not supported by cpuminer-opt due to an
incompatible implementation of SSE2 on these CPUs. 

More information for Intel and AMD CPU architectures and their features
can be found on Wikipedia.

https://en.wikipedia.org/wiki/List_of_Intel_CPU_microarchitectures

https://en.wikipedia.org/wiki/List_of_AMD_CPU_microarchitectures

File name                      Architecture name

cpuminer-sse2.exe              Core2, Nehalem, generic x86_64 with SSE2   
cpuminer-aes-sse42.exe         Westmere
cpuminer-avx.exe               Sandybridge, Ivybridge
cpuminer-avx2.exe              Haswell, Skylake, Kabylake, Coffeelake, Cometlake
cpuminer-avx2-sha.exe          AMD Zen1, Zen2
cpuminer-avx2-sha-vaes.exe     Intel Alderlake*, AMD Zen3
cpuminer-avx512.exe            Intel HEDT Skylake-X, Cascadelake
cpuminer-avx512-sha-vaes.exe   AMD Zen4, Intel Rocketlake, Icelake

* Alderlake is a hybrid architecture with a mix of E-cores & P-cores. Although
  the P-cores can support AVX512 the E-cores can't so Intel decided to disable
  AVX512 on the the P-cores.

Notes about included DLL files:

Downloading DLL files from alternative sources presents an inherent
security risk if their source is unknown. All DLL files included have
been copied from the Ubuntu-20.04 installation or compiled by me from
source code obtained from the author's official repository. The exact
procedure is documented in the build instructions for Windows:
https://github.com/JayDDee/cpuminer-opt/wiki/Compiling-from-source

Some included DLL files may already be installed on the system by Windows or
third party packages. They often will work and may be used instead of the
included version of the files.



If you like this software feel free to donate:

BTC: 12tdvfF7KmAsihBXQXynT6E6th2c2pByTT


