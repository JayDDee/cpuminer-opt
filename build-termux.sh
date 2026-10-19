#!/data/data/com.termux/files/usr/bin/bash
#
# Termux (Android, aarch64) build.
#
# Termux ships clang and no gcc. Nothing in the tree needs gcc, but two things
# differ from build-armv8.sh: CC has to be set explicitly, and clang on aarch64
# does not accept gcc's -march=native on every version, so the arch flag is
# probed here instead of hardcoded.
#
# Dependencies, once:
#
#   pkg install -y clang make autoconf automake libtool binutils libcurl libgmp
#
# jansson is deliberately not in that list: configure probes for it and falls
# back to the copy in compat/jansson, so no package is needed. The link needs
# curl, z, jansson, pthread, gmp and the C++ runtime -- z comes with libcurl and
# libc++ with clang, so libcurl and libgmp are the only real dependencies.
# Bionic keeps the pthread entry points in libc, so configure finding no
# libpthread is correct here rather than a problem.
#
# Usage:
#   bash build-termux.sh
#   ARCH_CFLAGS="-march=armv8-a+crypto" bash build-termux.sh   # force the flag
#   EXTRA_CFLAGS="-std=gnu17" bash build-termux.sh             # appended to CFLAGS
#
# EXTRA_CFLAGS is the escape hatch when a newer clang tightens a default: pinning
# -std=gnu17 undoes C23-era strictness without patching sources. Report anything
# that needs it, since the fix belongs in the code.

set -e

PREFIX=${PREFIX:-/data/data/com.termux/files/usr}
CC=${CC:-clang}
# dummy.cpp is in cpuminer_SOURCES, so automake links the program with the C++
# driver. Setting CXX matters: get it wrong and the build compiles every object
# and only then fails at the final link. Both come from the clang package.
CXX=${CXX:-clang++}
TMP=${TMPDIR:-/tmp}

command -v "$CC"  >/dev/null || { echo "$CC not found -- pkg install clang"; exit 1; }
command -v "$CXX" >/dev/null || { echo "$CXX not found -- pkg install clang"; exit 1; }

# Arch flag, best first: an explicit override, then -mcpu=native (which matches
# the SoC exactly when the compiler supports it), then a flag derived from what
# the kernel reports, then plain armv8-a. Only /proc/cpuinfo may enable +crypto:
# a flag that merely compiles proves nothing about the CPU, and guessing it wrong
# is a SIGILL at runtime.
probe() {
   echo 'int main(void){return 0;}' > "$TMP/cpm_probe.c"
   "$CC" $1 -c "$TMP/cpm_probe.c" -o "$TMP/cpm_probe.o" 2>/dev/null
}
has() { printf '%s' "$feat" | grep -qi "$1"; }

feat=$(grep -m1 -i '^Features' /proc/cpuinfo 2>/dev/null || true)
cands="${ARCH_CFLAGS:-}|-mcpu=native"
if has aes && has pmull; then
   has sha3 && cands="$cands|-march=armv8-a+crypto+sha3"
   cands="$cands|-march=armv8-a+crypto"
fi
cands="$cands|-march=armv8-a"

ARCH=""
IFS='|'
for cand in $cands; do
   [ -n "$cand" ] || continue
   if probe "$cand"; then ARCH="$cand"; break; fi
done
unset IFS
[ -n "$ARCH" ] || { echo "no usable arch flag -- is $CC working?"; exit 1; }

echo "compiler:   $($CC --version | head -1)  (CXX=$CXX)"
echo "arch flags: $ARCH"
if [ "$ARCH" = "-march=armv8-a" ]; then
   echo "note: no ARM crypto extensions detected, so verus and the hardware AES"
   echo "      paths of the x-family and GhostRider will compile out. If"
   echo "      /proc/cpuinfo hides the feature list, pass ARCH_CFLAGS."
fi

make distclean >/dev/null 2>&1 || true
rm -f config.status
./autogen.sh

CC="$CC" CXX="$CXX" \
   CFLAGS="-O3 $ARCH -Wall -flax-vector-conversions ${EXTRA_CFLAGS:-}" \
   CXXFLAGS="-O3 $ARCH" ./configure --with-curl="$PREFIX"

make -j"$(nproc 2>/dev/null || echo 4)"
command -v strip >/dev/null && strip cpuminer

cat <<'EOF'

Built. Start mining with:

  ./cpuminer -a ALGO -o stratum+tcps://POOL:PORT -u WALLET -p x -t 4

Android notes:
  termux-wake-lock            keep Android from suspending the miner
  --cpu-affinity 0xf0         thread N is pinned to cpu N by default, so on a
                              big.LITTLE SoC set a mask to stay on the big cores
EOF
