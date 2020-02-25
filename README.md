This cpuminer-opt is a fork of cpuminer-opt by Jay D Dee.
Special edit for armv7 and armv8 (aarch64)

All of the code is believed to be open and free. If anyone has a
claim to any of it post your case in the cpuminer-opt Bitcoin Talk forum
or by email.

https://github.com/JayDDee/cpuminer-opt
https://bitcointalk.org/index.php?topic=1326803.0
mailto://jayddee246@gmail.com
See file RELEASE_NOTES for change log and compile instructions.

Supported Algorithms
--------------------

                          argon2
                          bastion
                          blake        Blake-256 (SFR)
                          blakecoin    blake256r8
                          blake2s      Blake-2 S
                          bmw          BMW 256
                          cryptolight  Cryptonight-light
                          cryptonight  cryptonote, Monero (XMR)
                          decred
                          dmd-gr       Diamond-Groestl
                          groestl      Groestl coin
                          heavy        Heavy
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
                          pluck        Pluck:128 (Supcoin)
                          quark        Quark
                          scrypt       scrypt(1024, 1, 1) (default)
                          scrypt:N     scrypt(N, 1, 1)
                          scryptjane:nf
                          sha256d      Double SHA-256
                          sha256t      Triple SHA-256, Onecoin (OC)
                          shavite3     Shavite3
                          skein        Skein+Sha (Skeincoin)
                          skein2       Double Skein (Woodcoin)
                          vanilla      blake256r8vnl (VCash)
                          whirlpool
                          whirlpoolx
                          xevan        Bitsend
                          yescrypt     Globalboost-Y (BSTY)
                          yescryptr8   BitZeny (ZNY)\n\
                          yescryptr16  Yenten (YTN)
                          zr5          Ziftr

Unix install
------------
common code
    git clone https://github.com/glukolog/cpuminer-opt.git
    cd cpuminer-opt
    ./autogen.sh
    CFLAGS="-O3 -march=armv7l -mtune=cortex-a55" ./configure --with-curl --with-crypto
    make -j2
    ./cpuminer --help
for aarch64 configure string
    ./configure CFLAGS="-O3 -march=armv8-a+crypto -mtune=cortex-a53" --with-curl --with-crypto

Donations
---------

I do not do this for money but I have a donation address if users
are so inclined.

For Jay D Dee bitcoin:12tdvfF7KmAsihBXQXynT6E6th2c2pByTT?label=donations

Happy mining!

