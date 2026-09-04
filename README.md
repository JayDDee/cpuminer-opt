# cpuminer-opt

**A high-performance, multi-algorithm CPU miner** for Linux, Windows, MacOS and
BSD. Optimized for x86-64 (SSE2 / AVX2 / AVX512 / AES-NI / VAES) and aarch64
(NEON / ARMv8 crypto), with 100+ supported algorithms.

---

cpuminer-opt is a fork of cpuminer-multi by TPruvot with optimizations
imported from other miners developed by Lucas Jones, djm34, Wolf0, pooler,
Jeff Garzik, ig0tik3d, elmad, palmd, and Optiminer, with additional
optimizations by Jay D Dee.

All of the code is believed to be open and free. If anyone has a
claim to any of it post your case in the cpuminer-opt Bitcoin Talk forum
or by email.

Miner programs are often flagged as malware by antivirus programs. This is
a false positive, they are flagged simply because they are cryptocurrency 
miners. The source code is open for anyone to inspect. If you don't trust 
the software, don't use it.


- New thread: https://bitcointalk.org/index.php?topic=5226770.msg53865575#msg53865575
- Old thread: https://bitcointalk.org/index.php?topic=1326803.0
- Email: jayddee246@gmail.com

This note is to confirm that bitcointalk users JayDDee and joblo are the
same person.

I created a new BCT user JayDDee to match my github user id.
The old thread has been locked but still contains useful information for
reading.

See file RELEASE_NOTES for change log and INSTALL_LINUX or INSTALL_WINDOWS
for compile instructions. On Termux (Android, aarch64) use build-termux.sh,
which builds with clang; INSTALL_LINUX section 4b lists the packages.

Requirements
------------

1. A 64 bit CPU supporting x86_64 (Intel or AMD) or aarch64 (ARM).
x86_64 requires SSE2, aarch64 requires armv8 & NEON.

Mobile CPUs like laptop computers are not recommended because they aren't
designed for extreme heat of operating at full load for extended periods of
time.

2. 64 bit operating system including Linux, Windows, MacOS, or BSD.
Android, IOS and alt OSs like Haiku & ReactOS are not supported.

3. Stratum pool supporting stratum+tcp:// or stratum+ssl:// protocols or
RPC getblocktemplate using http:// or https://.

Supported Algorithms
--------------------

                          allium        Garlicoin
                          anime         Animecoin
                          argon2d250    
                          argon2d500
                          argon2d1000
                          argon2d16000
                          argon2d4096
                          argon2id1024  Bitweb (WEB)
                          axiom         Shabal-256 MemoHash
                          balloon       Mateable (MTBC)
                          blake         Blake-256
                          blake2b       Blake2-512
                          blake2s       Blake2-256
                          blakecoin     blake256r8
                          bmw           BMW 256
                          bmw512        BMW 512
                          c11           
                          curvehash     Pulsar (PLSR), alias curve
                          deep          Deepcoin (DCN)
                          dmd-gr        Diamond-Groestl
                          equihash      Equihash 200/9 (Zcash, Horizen, Komodo)
                          equihash96    Equihash 96/5
                          equihash125   Equihash 125/4 (Flux, ZelCash)
                          equihash144   Equihash 144/5 (Bitcoin Gold)
                          equihash192   Equihash 192/7 (ZeroClassic)
                          flex          Kylacoin
                          ghostrider    Raptoreum (RTM)
                          groestl       Groestl coin
                          heavyhash     Optical Bitcoin (OBTC), Ursula (URSA)
                          hex           x16r-hex
                          hmq1725       
                          hoohashv110   PepePow
                          jha           Jackpotcoin
                          k12           KangarooTwelve
                          keccak        Maxcoin
                          keccakc       Creative coin
                          lbry          LBC, LBRY Credits
                          lyra2h        
                          lyra2re       lyra2
                          lyra2rev2     lyra2v2
                          lyra2rev3     lyrav2v3
                          lyra2z        
                          lyra2z330     
                          m7m           
                          megabtx       Mega-BTX, BitCore (BTX)
                          megamec       Mega-MEC, Megacoin (MEC)
                          mike          VKAX, FortuneBlock (FTB)
                          minotaur 
                          minotaurx
                          myr-gr        Myriad-Groestl
                          neoscrypt     NeoScrypt(128, 2, 1)
                          neoscrypt-xaya Xaya (CHI), SpaceXpanse (ROD)
                          nist5         Nist5
                          odo           DigiByte (DGB)
                          panthera      Scala (XLA)
                          pentablake    Pentablake
                          phi1612       phi
                          phi2          
                          polytimos     Ninja
                          power2b       MicroBitcoin (MBC)
                          quark         Quark
                          qubit         Qubit
                          randomx       Monero (XMR), rx/0
                          randomx-sfx   Safex Cash (SFX), rx/sfx
                          randomx-arq   ArQmA (ARQ), rx/arq
                          randomx-graft Graft (GRFT), rx/graft
                          randomx-wow   Wownero (WOW), rx/wow
                          rinhash       RinCoin (RIN)
                          scrypt        scrypt(1024, 1, 1) (default)
                          scrypt:N      scrypt(N, 1, 1)
                          scryptn2      scrypt(1048576, 1, 1)
                          sha256csm     SHA-256d over a 112-byte header, Galleoncoin (GALE)
                          sha256d       Double SHA-256
                          sha256dt
                          sha256dv      SHA-256D Veil
                          sha256q       Quad SHA-256
                          sha256t       Triple SHA-256
                          sha3d         Double keccak256 (BSHA3)
                          sha3t         Triple SHA3-256, BitcoinIII (BC3), Fjarcode (FJAR)
                          sha512256d
                          skein         Skein+Sha (Skeincoin)
                          skein2        Double Skein (Woodcoin)
                          skunk         Signatum (SIGT)
                          skydoge       SkyDoge
                          sonoa         Sono
                          soterg        Soteria (SOTER)
                          timetravel    Machinecoin (MAC)
                          timetravel10  Bitcore
                          tribus        Denarius (DNR)
                          vanilla       blake256r8vnl (VCash)
                          veltor        (VLT)
                          verthash      Vertcoin
                          verus         VerusHash 2.2 (Verus Coin)
                          whirlpool
                          whirlpoolx
                          whirlpoolx2   CapStash (CAP)
                          x11           Dash
                          x11evo        Revolvercoin
                          x11gost       sib (SibCoin)
                          x12           
                          x13           
                          x13bcd        bcd
                          x13sm3        hsr (Hshare)
                          x14           
                          x15           
                          x16r          
                          x16rv2        
                          x16rt         
                          x16rt-veil    veil
                          x16s          
                          x17
                          x20r
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
                          yespoweradvc  AdventureCoin (ADVC)
                          yespowereqpay EquityPay (EQPAY)
                          yespowerltncg Crionic (CRNC)
                          yespowermgpc  MagpieCoin (MGPC)
                          yespowerr16   Yenten (YTN)
                          yespowersugar Sugarchain (SUGAR)
                          yespowertide  Tidecoin (TDC)
                          yespowerurx   UraniumX (URX)
                          yespower-b2b  generic yespower + blake2b
                          zr5           Ziftr

Many variations of scrypt based algos can be mine by specifying their
parameters:

Some yespower variants also have a named algo, listed above. Prefer the named
form where one exists: it carries the coin's parameters and checks them against
a known-answer test at startup, so a wrong parameter refuses to start rather
than mining shares the pool rejects. See docs/algorithms/yescrypt-yespower.md
for the parameter table and where each set was sourced from.

scryptn2: --algo scrypt --param-n 1048576

cpupower: --algo yespower --param-key "CPUpower: The number of CPU working or available for proof-of-work mining"

power2b: --algo yespower-b2b --param-n 2048 --param-r 32 --param-key "Now I am become Death, the destroyer of worlds"

sugarchain: --algo yespowersugar

yespoweriots: --algo yespower --param-n 2048 --param-key "Iots is committed to the development of IOT"

yespowerlitb: --algo yespower --param-n 2048 --param-r 32 --param-key "LITBpower: The number of LITB working or available for proof-of-work mini"

yespoweric: --algo yespower --param-n 2048 --param-r 32 --param-key "IsotopeC" 

yespowerurx: --algo yespower --param-n 2048 --param-r 32 --param-key "UraniumX"

yespowerltncg: --algo yespowerltncg

Errata
------

Old algorithms that are no longer used frequently will not have the latest
optimizations.

Standalone Cryptonight algos are no longer supported, use another miner. The
algos that embed CryptoNight cores as one stage of a chain, gr (Raptoreum) and
mike (VKAX, FortuneBlock), are supported.

Neoscrypt crashes on Windows, use legacy version.

AMD CPUs older than Piledriver, including Athlon x2 and Phenom II x4, are not
supported by cpuminer-opt due to an incompatible implementation of SSE2 on
these CPUs. Some algos may crash the miner with an invalid instruction.
Users are recommended to use an unoptimized miner such as cpuminer-multi.

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

Jay D Dee (maintainer):

 BTC: 12tdvfF7KmAsihBXQXynT6E6th2c2pByTT

tpfuemp (argon2id1024, balloon, curvehash, equihash, flex, ghostrider,
heavyhash, hoohashv110, megabtx, megamec, mike, odo, sha256dv, sha3t, skydoge
and verus additions):

 DOGE: DNQdyeLu9DtRfsZCFvy1GfJTwjWJoSWHLh

Happy mining!

