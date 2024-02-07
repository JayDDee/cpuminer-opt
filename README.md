# cpuminer-opt

cpuminer-opt is a fork of cpuminer-multi by TPruvot with optimizations imported from other miners developed by Lucas Jones, djm34, Wolf0, pooler, Jeff Garzik, ig0tik3d, elmad, palmd, and Optiminer, with additional optimizations by Jay J Dee.

All of the code is believed to be open and free. If anyone has a claim to any of it, please post your case in the cpuminer-opt Bitcoin Talk forum or by email.

Miner programs are often flagged as malware by antivirus programs. This is a false positive; they are flagged simply because they are cryptocurrency miners. The source code is open for anyone to inspect. If you don't trust the software, don't use it.

**New Thread**: [Bitcoin Talk Forum](https://bitcointalk.org/index.php?topic=5226770.msg53865575#msg53865575)

**Old Thread**: [Bitcoin Talk Forum](https://bitcointalk.org/index.php?topic=1326803.0)

**Contact**: [jayddee246@gmail.com](mailto:jayddee246@gmail.com)

*Note*: This note is to confirm that Bitcointalk users JayDDee and joblo are the same person. I created a new BCT user JayDDee to match my GitHub user ID. The old thread has been locked but still contains useful information for reading.

See file `RELEASE_NOTES` for the changelog and `INSTALL_LINUX` or `INSTALL_WINDOWS` for compile instructions.

## Requirements

1. A x86_64 architecture CPU with a minimum of SSE2 support. This includes Intel Core2 and newer and AMD equivalents. Further optimizations are available on some algorithms for CPUs with AES, AVX, AVX2, SHA, AVX512, and VAES. 32-bit CPUs are not supported. Other CPU architectures such as ARM, Raspberry Pi, RISC-V, Xeon Phi, etc., are not supported. Mobile CPUs like laptop computers are not recommended because they aren't designed for the extreme heat of operating at full load for extended periods of time. Older CPUs and ARM architecture may be supported by cpuminer-multi by TPruvot.

2. 64-bit Linux or Windows OS. Ubuntu and Fedora-based distributions, including Mint and CentOS, are known to work and have all dependencies in their repositories. Others may work but may require more effort. Older versions such as CentOS 6 don't work due to missing features. Windows 7 or newer is supported with mingw_w64 and MSYS or using the pre-built binaries. Windows XP 64-bit is YMMV. FreeBSD is not actively tested but should work, YMMV. MacOS, OS X, and Android are not supported.

3. Stratum pool supporting `stratum+tcp://` or `stratum+ssl://` protocols or RPC getwork using `http://` or `https://`. GBT is YMMV.

## Supported Algorithms

- `allium`: Garlicoin
- `anime`: Animecoin
- `argon2`: Argon2 coin (AR2)
- `argon2d250`: Argon2d-crds, Credits (CRDS)
- `argon2d500`: Argon2d-dyn, Dynamic (DYN)
- `argon2d4096`: Argon2d-uis, Unitus, (UIS)
- `blake`: Blake-256
- `blake2b`: Blake2-512
- `blake2s`: Blake2-256
- `blakecoin`: Blake256r8
- `bmw`: BMW 256
- `bmw512`: BMW 512
- `c11`
- `decred`
- `deep`: Deepcoin (DCN)
- `dmd-gr`: Diamond-Groestl
- `groestl`: Groestl coin
- `hex`: x16r-hex
- `hmq1725`
- `jha`: Jackpotcoin
- `keccak`: Maxcoin
- `keccakc`: Creative coin
- `lbry`: LBC, LBRY Credits
- `lyra2h`
- `lyra2re`: Lyra2
- `lyra2rev2`: Lyra2v2
- `lyra2rev3`: Lyra2v3
- `lyra2z`
- `lyra2z330`
- `m7m`
- `minotaur`
- `minotaurx`
- `myr-gr`: Myriad-Groestl
- `neoscrypt`: NeoScrypt(128, 2, 1)
- `nist5`: Nist5
- `pentablake`: Pentablake
- `phi1612`: Phi
- `phi2`
- `polytimos`: Ninja
- `power2b`: MicroBitcoin (MBC)
- `quark`: Quark
- `qubit`: Qubit
- `scrypt`: scrypt(1024, 1, 1) (default)
- `scrypt:N`: scrypt(N, 1, 1)
- `scryptn2`: scrypt(1048576, 1, 1)
- `sha256d`: Double SHA-256
- `sha256dt`
- `sha256q`: Quad SHA-256
- `sha256t`: Triple SHA-256
- `sha3d`: Double keccak256 (BSHA3)
- `sha512256d`
- `skein`: Skein+Sha (Skeincoin)
- `skein2`: Double Skein (Woodcoin)
- `skunk`: Signatum (SIGT)
- `sonoa`: Sono
- `timetravel`: Machinecoin (MAC)
- `timetravel10`: Bitcore
- `tribus`: Denarius (DNR)
- `vanilla`: Blake256r8vnl (VCash)
- `veltor` (VLT)
- `verthash`: Vertcoin
- `whirlpool`
- `whirlpoolx`
- `x11`: Dash
- `x11evo`: Revolvercoin
- `x11gost`: Sib (SibCoin)
- `x12`
- `x13`
- `x13bcd`: BCD
- `x13sm3`: HSR (Hshare)
- `x14`
- `x15`
- `x16r`
- `x16rv2`
- `x16rt`
- `x16rt-veil`: Veil
- `x16s`
- `x17`
- `x20r`
- `x21s`
- `x22i`
- `x25x`
- `xevan`: Bitsend (BSD)
- `yescrypt`: Globalboost-Y (BSTY)
- `yescryptr8`: BitZeny (ZNY)
- `yescryptr8g`: Koto (KOTO)
- `yescryptr16`: Eli
- `yescryptr32`: WAVI
- `yespower`: Cryply
- `yespowerr16`: Yenten (YTN)
- `yespower-b2b`: Generic yespower + blake2b
- `zr5`: Ziftr

Many variations of scrypt-based algos can be mined by specifying their parameters:

- `scryptn2`: `--algo scrypt --param-n 1048576`
- `cpupower`: `--algo yespower --param-key "CPUpower: The number of CPU working or available for proof-of-work mining"`
- `power2b`: `--algo yespower-b2b --param-n 2048 --param-r 32 --param-key "Now I am become Death, the destroyer of worlds"`
- `sugarchain`: `--algo yespower --param-n 2048 -param-r 32 --param-key "Satoshi Nakamoto 31/Oct/2008 Proof-of-work is essentially one-CPU-one-vote"`
- `yespoweriots`: `--algo yespower --param-n 2048 --param-key "Iots is committed to the development of IOT"`
- `yespowerlitb`: `--algo yespower --param-n 2048 --param-r 32 --param-key "LITBpower: The number of LITB working or available for proof-of-work mini"`
- `yespoweric`: `--algo yespower --param-n 2048 --param-r 32 --param-key "IsotopeC"`
- `yespowerurx`: `--algo yespower --param-n 2048 --param-r 32 --param-key "UraniumX"`
- `yespowerltncg`: `--algo yespower --param-n 2048 --param-r 32 --param-key "LTNCGYES"`

## Errata

- Old algorithms that are no longer used frequently will not have the latest optimizations.
- Cryptonight and variants are no longer supported, use another miner.
- Neoscrypt crashes on Windows, use legacy version.
- AMD CPUs older than Piledriver, including Athlon x2 and Phenom II x4, are not supported by cpuminer-opt due to an incompatible implementation of SSE2 on these CPUs. Some algos may crash the miner with an invalid instruction. Users are recommended to use an unoptimized miner such as cpuminer-multi.
- cpuminer-opt does not work mining Decred algo at Nicehash and produces only "invalid extranonce2 size" rejects.
- Benchmark testing does not work for x11evo.

## Bugs

Users are encouraged to post their bug reports using git issues or on the Bitcoin Talk forum or opening an issue in git:

- [Bitcoin Talk Forum](https://bitcointalk.org/index.php?topic=1326803.0)
- [GitHub Issues](https://github.com/JayDDee/cpuminer-opt/issues)

All problem reports must be accompanied by a proper problem definition. This should include how the problem occurred, the command line and output from the miner showing the startup messages and any errors. A history is also useful, i.e., did it work before.

## Donations

cpuminer-opt has no fees of any kind but donations are accepted.

- BTC: 12tdvfF7KmAsihBXQXynT6E6th2c2pByTT

Happy mining!
