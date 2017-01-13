cpuminer-opt is a fork of cpuminer-multi by TPruvot with optimizations
imported from other miners developped by lucas Jones, djm34, Wolf0, pooler,
Jeff garzik, ig0tik3d, elmad, palmd, and Optiminer, with additional
optimizations by Jay D Dee.

All of the code is believed to be open and free. If anyone has a
claim to any of it post your case in the icpuminer-opt Bitcoin Talk forum
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
                          c11          Flax
                          cryptolight  Cryptonight-light
                          cryptonight  cryptonote, Monero (XMR)
                          decred
                          drop         Dropcoin
                          fresh        Fresh
                          groestl      groestl
                          heavy        Heavy
                          hmq1725      Espers
                          hodl         Hodlcoin
                          keccak       Keccak
                          lbry         LBC, LBRY Credits
                          luffa        Luffa
                          lyra2re      lyra2
                          lyra2rev2    lyrav2
                          lyra2z       Zcoin (XZC)
                          lyra2zoin    Zoin (ZOI)
                          m7m          Magi (XMG)
                          myr-gr       Myriad-Groestl
                          neoscrypt    NeoScrypt(128, 2, 1)
                          nist5        Nist5
                          pluck        Pluck:128 (Supcoin)
                          pentablake   Pentablake
                          quark        Quark
                          qubit        Qubit
                          scrypt       scrypt(1024, 1, 1) (default)
                          scrypt:N     scrypt(N, 1, 1)
                          scryptjane:nf
                          sha256d      SHA-256d
                          shavite3     Shavite3
                          skein        Skein+Sha (Skeincoin)
                          skein2       Double Skein (Woodcoin)
                          vanilla      blake256r8vnl (VCash)
                          veltor
                          whirlpool
                          whirlpoolx
                          x11          X11
                          x11evo       Revolvercoin
                          x11gost      sib (SibCoin)
                          x13          X13
                          x14          X14
                          x15          X15
                          x17
                          xevan        Bitsend
                          yescrypt
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

2. 64 bit Linux OS. Ubuntu and Fedora based distributions, including Mint and
Centos are known to work and have all dependencies in their repositories.
Others may work but may require more effort. 64 bit Windows OS is now supported
with mingw_w64 and msys.

3. Stratum pool, cpuminer-opt only supports stratum minning.

Errata
------

cpuminer-opt does not work mining Decred algo at Nicehash and produces
only "invalid extranonce2 size" rejects. It works at Zpool.

Benchmark testing does not work for x11evo.

Bugs
----

Users are encouraged to post their bug reports on the Bitcoin Talk
forum at:

https://bitcointalk.org/index.php?topic=1326803.0

Donations
---------

I do not do this for money but I have a donation address if users
are so inclined.

bitcoin:12tdvfF7KmAsihBXQXynT6E6th2c2pByTT?label=donations

Happy mining!

