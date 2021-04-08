cpuminer-opt is a fork of cpuminer-multi by TPruvot with optimizations
imported from other miners developped by lucas Jones, djm34, Wolf0, pooler,
Jeff garzik, ig0tik3d, elmad, palmd, and Optiminer, with additional
optimizations by Jay D Dee.

All of the code is believed to be open and free. If anyone has a
claim to any of it post your case in the cpuminer-opt Bitcoin Talk forum
or by email.

Miner programs are often flagged as malware by antivirus programs. This is
a false positive, they are flagged simply because they are cryptocurrency 
miners. The source code is open for anyone to inspect. If you don't trust 
the software, don't use it.


New thread:

https://bitcointalk.org/index.php?topic=5226770.msg53865575#msg53865575

Old thread:

https://bitcointalk.org/index.php?topic=1326803.0

mailto://jayddee246@gmail.com

This note is to confirm that bitcointalk users JayDDee and joblo are the
same person.

I created a new BCT user JayDDee to match my github user id.
The old thread has been locked but still contains useful information for
reading.

See file RELEASE_NOTES for change log and INSTALL_LINUX or INSTALL_WINDOWS
for compile instructions.

Requirements
------------

1. A x86_64 architecture CPU with a minimum of SSE2 support. This includes
Intel Core2 and newer and AMD equivalents. Further optimizations are available
on some algoritms for CPUs with AES, AVX, AVX2, SHA, AVX512 and VAES.

Older CPUs are supported by cpuminer-multi by TPruvot but at reduced
performance.

ARM and Aarch64 CPUs are not supported.

2. 64 bit Linux or Windows OS. Ubuntu and Fedora based distributions,
including Mint and Centos, are known to work and have all dependencies
in their repositories. Others may work but may require more effort. Older
versions such as Centos 6 don't work due to missing features. 
64 bit Windows OS is supported with mingw_w64 and msys or pre-built binaries.

MacOS, OSx and Android are not supported.

3. Stratum pool supporting stratum+tcp:// or stratum+ssl:// protocols or
RPC getwork using http:// or https://.
GBT is YMMV.

Supported Algorithms
--------------------

                          allium        Garlicoin
                          anime         Animecoin
                          argon2        Argon2 coin (AR2)
                          argon2d250    argon2d-crds, Credits (CRDS)
                          argon2d500    argon2d-dyn,  Dynamic (DYN)
                          argon2d4096   argon2d-uis, Unitus, (UIS)
                          axiom         Shabal-256 MemoHash
                          blake         Blake-256 (SFR)
                          blake2b       Blake2b 256
                          blake2s       Blake-2 S
                          blakecoin     blake256r8
                          bmw           BMW 256
                          bmw512        BMW 512
                          c11           Chaincoin
                          decred
                          deep          Deepcoin (DCN)
                          dmd-gr        Diamond-Groestl
                          groestl       Groestl coin
                          hex           x16r-hex
                          hmq1725       Espers
                          hodl          Hodlcoin
                          jha           Jackpotcoin
                          keccak        Maxcoin
                          keccakc       Creative coin
                          lbry          LBC, LBRY Credits
                          luffa         Luffa
                          lyra2h        Hppcoin
                          lyra2re       lyra2
                          lyra2rev2     lyra2v2
                          lyra2rev3     lyrav2v3
                          lyra2z        
                          lyra2z330     Lyra2 330 rows, Zoin (ZOI)
                          m7m           Magi (XMG)
                          minotaur      Ringcoin (RNG)
                          myr-gr        Myriad-Groestl
                          neoscrypt     NeoScrypt(128, 2, 1)
                          nist5         Nist5
                          pentablake    Pentablake
                          phi1612       phi
                          phi2          Luxcoin (LUX)
                          phi2-lux      identical to phi2
                          pluck         Pluck:128 (Supcoin)
                          polytimos     Ninja
                          power2b       MicroBitcoin (MBC)
                          quark         Quark
                          qubit         Qubit
                          scrypt        scrypt(1024, 1, 1) (default)
                          scrypt:N      scrypt(N, 1, 1)
                          sha256d       Double SHA-256
                          sha256q       Quad SHA-256, Pyrite (PYE)
                          sha256t       Triple SHA-256, Onecoin (OC)
                          sha3d         Double keccak256 (BSHA3)
                          shavite3      Shavite3
                          skein         Skein+Sha (Skeincoin)
                          skein2        Double Skein (Woodcoin)
                          skunk         Signatum (SIGT)
                          sonoa         Sono
                          timetravel    Machinecoin (MAC)
                          timetravel10  Bitcore
                          tribus        Denarius (DNR)
                          vanilla       blake256r8vnl (VCash)
                          veltor        (VLT)
                          verthash      Vertcoin
                          whirlpool
                          whirlpoolx
                          x11           Dash
                          x11evo        Revolvercoin
                          x11gost       sib (SibCoin)
                          x12           Galaxie Cash (GCH)
                          x13           X13
                          x13bcd        bcd
                          x13sm3        hsr (Hshare)
                          x14           X14
                          x15           X15
                          x16r          
                          x16rv2        
                          x16rt         Gincoin (GIN)
                          x16rt-veil    Veil (VEIL)
                          x16s          Pigeoncoin (PGN)
                          x17
                          x21s
                          x22i
                          x25x
                          xevan         Bitsend (BSD)
                          yescrypt      Globalboost-Y (BSTY)
                          yescryptr8    BitZeny (ZNY)
                          yescryptr8g   Koto (KOTO)
                          yescryptr16   Eli
                          yescryptr32   WAVI
                          yespower      Cryply
                          yespowerr16   Yenten (YTN)
                          yespower-b2b  generic yespower + blake2b
                          zr5           Ziftr

Many variations of scrypt based algos can be mine by specifying their
parameters:

scryptn2: --algo scrypt --param-n 1048576

cpupower: --algo yespower --param-key "CPUpower: The number of CPU working or available for proof-of-work mining"

power2b: --algo yespower-b2b --param-n 2048 --param-r 32 --param-key "Now I am become Death, the destroyer of worlds"

sugarchain: --algo yespower --param-n 2048 -param-r 32 --param-key "Satoshi Nakamoto 31/Oct/2008 Proof-of-work is essentially one-CPU-one-vote"

yespoweriots: --algo yespower --param-n 2048 --param-key "Iots is committed to the development of IOT"

yespowerlitb: --algo yespower --param-n 2048 --param-r 32 --param-key "LITBpower: The number of LITB working or available for proof-of-work mini"

yespoweric: --algo yespower --param-n 2048 --param-r 32 --param-key "IsotopeC" 

yespowerurx: --algo yespower --param-n 2048 --param-r 32 --param-key "UraniumX"

yespowerltncg: --algo yespower --param-n 2048 --param-r 32 --param-key "LTNCGYES"

Errata
------

Old algorithms that are no longer used frequently will not have the latest
optimizations.

Cryptonight and variants are no longer supported, use another miner.

Neoscrypt crashes on Windows, use legacy version.

AMD CPUs older than Piledriver, including Athlon x2 and Phenom II x4, are not
supported by cpuminer-opt due to an incompatible implementation of SSE2 on
these CPUs. Some algos may crash the miner with an invalid instruction.
Users are recommended to use an unoptimized miner such as cpuminer-multi.

cpuminer-opt does not work mining Decred algo at Nicehash and produces
only "invalid extranonce2 size" rejects.

Benchmark testing does not work for x11evo.

Bugs
----

Users are encouraged to post their bug reports using git issues or on the
Bitcoin Talk forum or opening an issue in git:

https://bitcointalk.org/index.php?topic=1326803.0

https://github.com/JayDDee/cpuminer-opt/issues

All problem reports must be accompanied by a proper problem definition.
This should include how the problem occurred, the command line and
output from the miner showing the startup messages and any errors.
A history is also useful, ie did it work before.

Donations
---------

cpuminer-opt has no fees of any kind but donations are accepted.

 BTC: 12tdvfF7KmAsihBXQXynT6E6th2c2pByTT

Happy mining!

