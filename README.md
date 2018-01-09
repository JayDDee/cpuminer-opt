cpuminer-opt is a fork of cpuminer-multi by TPruvot with optimizations
imported from other miners developped by lucas Jones, djm34, Wolf0, pooler,
Jeff garzik, ig0tik3d, elmad, palmd, and Optiminer, with additional
optimizations by Jay D Dee.

All of the code is believed to be open and free. If anyone has a
claim to any of it post your case in the cpuminer-opt Bitcoin Talk forum
or by email.

https://bitcointalk.org/index.php?topic=1326803.0

mailto://jayddee246@gmail.com

See file RELEASE_NOTES for change log and compile instructions.

Supported Algorithms
--------------------

                          argon2
                          axiom        Shabal-256 MemoHash
                          bastion
                          blake        Blake-256 (SFR)
                          blakecoin    blake256r8
                          blake2s      Blake-2 S
                          bmw          BMW 256
                          c11          Chaincoin
                          cryptolight  Cryptonight-light
                          cryptonight  cryptonote, Monero (XMR)
                          decred
                          deep         Deepcoin (DCN)
                          dmd-gr       Diamond-Groestl
                          drop         Dropcoin
                          fresh        Fresh
                          groestl      Groestl coin
                          heavy        Heavy
                          hmq1725      Espers
                          hodl         Hodlcoin
                          jha          Jackpotcoin
                          keccak       Maxcoin
                          keccakc      Creative coin
                          lbry         LBC, LBRY Credits
                          luffa        Luffa
                          lyra2h       Hppcoin
                          lyra2re      lyra2
                          lyra2rev2    lyra2v2, Vertcoin
                          lyra2z       Zcoin (XZC)
                          lyra2z330    Lyra2 330 rows, Zoin (ZOI)
                          m7m          Magi (XMG)
                          myr-gr       Myriad-Groestl
                          neoscrypt    NeoScrypt(128, 2, 1)
                          nist5        Nist5
                          pentablake   Pentablake
                          phi1612      phi, LUX coin
                          pluck        Pluck:128 (Supcoin)
                          polytimos    Ninja
                          quark        Quark
                          qubit        Qubit
                          scrypt       scrypt(1024, 1, 1) (default)
                          scrypt:N     scrypt(N, 1, 1)
                          scryptjane:nf
                          sha256d      Double SHA-256
                          sha256t      Triple SHA-256, Onecoin (OC)
                          shavite3     Shavite3
                          skein        Skein+Sha (Skeincoin)
                          skein2       Double Skein (Woodcoin)
                          skunk        Signatum (SIGT)
                          timetravel   Machinecoin (MAC)
                          timetravel10 Bitcore
                          tribus       Denarius (DNR)
                          vanilla      blake256r8vnl (VCash)
                          veltor       (VLT)
                          whirlpool
                          whirlpoolx
                          x11          Dash
                          x11evo       Revolvercoin
                          x11gost      sib (SibCoin)
                          x13          X13
                          x13sm3       hsr (Hshare)
                          x14          X14
                          x15          X15
                          x17
                          xevan        Bitsend
                          yescrypt     Globalboost-Y (BSTY)
                          yescryptr8   BitZeny (ZNY)\n\
                          yescryptr16  Yenten (YTN)
                          zr5          Ziftr

Requirements
------------

1. A x86_64 architecture CPU with a minimum of SSE2 support. This includes
Intel Core2 and newer and AMD equivalents. In order to take advantage of AES_NI
optimizations a CPU with AES_NI is required. This includes Intel Westbridge
and newer and AMD equivalents. Further optimizations are available on some
algoritms for CPUs with AVX and AVX2, Sandybridge and Haswell respectively.

Older CPUs are supported by cpuminer-multi by TPruvot but at reduced
performance.

ARM CPUs are not supported.

2. 64 bit Linux OS. Ubuntu and Fedora based distributions, including Mint and
Centos are known to work and have all dependencies in their repositories.
Others may work but may require more effort.
64 bit Windows OS is supported with mingw_w64 and msys or pre-built binaries.

MacOS, OSx is not supported.

3. Stratum pool. Some algos may work wallet mining using getwork.

Errata
------

AMD CPUs older than Piledriver, including Athlon x2 and Phenom II x4, are not
supported by cpuminer-opt due to an incompatible implementation of SSE2 on
these CPUs. Some algos may crash the miner with an invalid instruction.
Users are recommended to use an unoptimized miner such as cpuminer-multi.

cpuminer-opt does not work mining Decred algo at Nicehash and produces
only "invalid extranonce2 size" rejects.

Benchmark testing does not work for x11evo.

Bugs
----

Users are encouraged to post their bug reports on the Bitcoin Talk
forum at:

https://bitcointalk.org/index.php?topic=1326803.0

All problem reports must be accompanied by a proper definition.
This should include how the problem occurred, the command line and
output from the miner showing the startup and any errors.

Donations
---------

I do not do this for money but I have a donation address if users
are so inclined.

bitcoin:12tdvfF7KmAsihBXQXynT6E6th2c2pByTT?label=donations

Happy mining!

