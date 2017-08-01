This file is included in the Windows binary package. Compile instructions
for Linux and Windows can be found in RELEASE_NOTES.

cpuminer is a console program that is executed from a DOS command prompt.
There is no GUI and no mouse support.

Choose the exe that best matches you CPU's features or use trial and
error to find the fastest one that doesn't crash. Pay attention to
the features listed at cpuminer startup to ensure you are mining at
optimum speed using all the available features.

Architecture names and compile options used are only provided for Intel
Core series. Pentium and Celeron often have fewer features.
AMD is YMMV, see previous paragraph.

Exe name                  Compile opts       Arch name

cpuminer-sse2.exe         -march=core2,      Core2   
cpuminer-sse42.exe        -march=corei7,     Nehalem
cpuminer-aes-sse42.exe    -maes -msse4.2     Westmere
cpuminer-aes-avx.exe      -march=corei7-avx, Sandybridge, Ivybridge
cpuminer-aes-avx2.exe     -march=core-avx2,  Haswell, Broadwell, Skylake, Kabylake



