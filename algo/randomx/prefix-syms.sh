#!/bin/sh
# Prefix the symbols a second copy of the RandomX core defines in ORDINARY
# sections, so it can be linked alongside the stock one.
#
#   prefix-syms.sh <in.a> <out.a> <prefix> [nm] [objcopy]
#
# Not objcopy --prefix-symbols: that renames UNDEFINED symbols too, so every
# reference to libc and libstdc++ gets the prefix and the link fails.
#
# The C++ half is done earlier, by the compiler: Makefile.am builds each
# variant with -Drandomx=<ns> plus one -D per opaque C API type. Left here are
# the ordinary-section definitions -- the extern "C" API, the vendored argon2
# and blake2b, the JIT's assembly labels, and the few functions upstream
# leaves in the global namespace (cpuid, soft_aesenc, soft_aesdec).
#
# Two constraints, both load-bearing:
#
#   1. Never rename a COMDAT. Its section is named after its symbol and
#      objcopy does not rename the section, so PE discards the definition and
#      ELF discards the whole group. Detection differs by format: ELF marks
#      them weak (nm W/V); PE has no weak binding and names a section after
#      the symbol instead, so most PE COMDATs look strong.
#   2. A PE `.refptr.X` stub must move with X, or it collides with the stock
#      core's stub of the same name and the linker keeps one for both cores --
#      silent cross-core aliasing, not a link error. Moving one means three
#      names: the stub symbol, its section, and the section-name symbol the
#      linker reports as the COMDAT symbol.
#
# A partial rename binds a variant entry point to stock internals, which mines
# the wrong algorithm while looking healthy; the post-checks below refuse it.

set -e

IN="$1"; OUT="$2"; PREFIX="$3"
NM="${4:-nm}"; OBJCOPY="${5:-objcopy}"

if [ -z "$IN" ] || [ -z "$OUT" ] || [ -z "$PREFIX" ]; then
   echo "usage: $0 <in.a> <out.a> <prefix> [nm] [objcopy]" >&2
   exit 1
fi

# The namespace the compiler already renamed, derived from the prefix so the
# two cannot disagree: prefix rxwow_ means namespace rxwow.
NS=$(echo "$PREFIX" | sed 's/_$//')

MAP="$OUT.syms"
ALL="$OUT.allsyms"
COMDAT="$OUT.comdat"

# name + type for every defined symbol. The NF/type guard drops the
# "archive[member.o]:" separator lines, whose member names contain "randomx"
# and would otherwise enter the rename map.
defs()
{
   "$NM" --defined-only --format=posix "$1" \
     | awk 'NF >= 2 && $2 ~ /^[A-Za-z]$/ { print $1, $2 }'
}

# Names that own a section named after them: PE COMDATs. Empty on ELF.
comdat_names()
{
   sed -n 's/^\.[^$]*\$\(.*\) [A-Za-z]$/\1/p' | sort -u
}

# Definitions in ordinary sections: global (uppercase type), not ELF-weak.
plain_globals()
{
   awk '$2 ~ /^[A-Z]$/ && $2 != "W" && $2 != "V" { print $1 }' | sort -u
}

defs "$IN" > "$OUT.defs"
comdat_names < "$OUT.defs" > "$COMDAT"
# Skip anything already prefixed, so the rule is idempotent.
plain_globals < "$OUT.defs" | grep -v "^$PREFIX" > "$ALL"

# Not ours, or handled separately:
#   .refptr.*      PE indirection stubs. Kept out of the map here because they
#                  are not renamed like an ordinary symbol -- they move with
#                  their target, section and all, further down.
#   __*, DW.ref.*  compiler and unwinder helpers.
#   _Z...St<n>...  std:: mangled names, if any survived the COMDAT filter.
# Also skipped: anything already carrying the variant's namespace, which the
# compiler made unique -- renaming it again would only add noise.
NOTOURS='^\.refptr\.|^__|^DW\.ref\.|^_ZSt|^_Z[A-Za-z]*N?K?St[0-9]'

grep -E "$NOTOURS" "$ALL" > "$OUT.keep" || true
grep -F "$NS" "$ALL" >> "$OUT.keep" || true
cat "$COMDAT" >> "$OUT.keep"
sort -u "$OUT.keep" -o "$OUT.keep"

# The rename map is everything else.
if [ -s "$OUT.keep" ]; then
   grep -v -x -F -f "$OUT.keep" "$ALL" > "$MAP.names" || true
else
   cp "$ALL" "$MAP.names"
fi
awk -v p="$PREFIX" '{ print $1 " " p $1 }' "$MAP.names" > "$MAP"

# PE indirection stubs: `.refptr.X` holds the address of X, so it must move
# with X (rule 2 above). No-op on ELF, which has no such stubs.
SECTARGS=
grep -E '^\.refptr\.' "$OUT.defs" | awk '{ print $1 }' | sort -u > "$OUT.refptr"
while read -r stub; do
   [ -n "$stub" ] || continue
   target=$(echo "$stub" | sed 's/^[.]refptr[.]//')
   grep -qx "$target" "$MAP.names" || continue      # target not ours: leave it
   echo "$stub $PREFIX$stub" >> "$MAP"
   # Its section, e.g. .rdata$.refptr.X -- read the real name from nm rather
   # than assuming .rdata. Must be $( ) and not backticks: backticks eat the
   # backslash in the awk regex, and ^[^$]*$ matches nothing here.
   sect=$(awk -v s="$stub" '{ n = $1; if (sub(/^[^$]*\$/, "", n) && n == s) print $1 }' \
          "$OUT.defs" | sort -u | head -1)
   if [ -n "$sect" ]; then
      grp=$(echo "$sect" | sed 's/[$].*//')
      SECTARGS="$SECTARGS --rename-section $sect=$grp\$$PREFIX$stub"
      # The section-name symbol too: that is the one the linker reports as the
      # COMDAT symbol, so leaving it warns on every stub.
      echo "$sect $grp\$$PREFIX$stub" >> "$MAP"
   fi
done < "$OUT.refptr"

COUNT=`grep -c '' "$MAP" || true`
KEPT=`grep -c '' "$OUT.keep" || true`
if [ "$COUNT" -eq 0 ]; then
   echo "$0: refusing to continue -- nothing renameable found in $IN" >&2
   echo "  (an empty rename map would produce an unprefixed copy, which links" >&2
   echo "   against the stock core and mines the wrong algorithm silently)" >&2
   exit 1
fi

cp "$IN" "$OUT"
"$OBJCOPY" --redefine-syms="$MAP" $SECTARGS "$OUT"

# Prove it took: the archive must now define the prefixed C entry point and
# must no longer define the bare one.
if ! defs "$OUT" | plain_globals | grep -qx "${PREFIX}randomx_calculate_hash"; then
   echo "$0: ${PREFIX}randomx_calculate_hash is not defined in $OUT" >&2
   exit 1
fi
if defs "$OUT" | plain_globals | grep -qx "randomx_calculate_hash"; then
   echo "$0: $OUT still defines the unprefixed randomx_calculate_hash" >&2
   exit 1
fi

# The skip list above is only safe if it skipped nothing of the core's own.
# Enforce it: no ordinary-section definition may still name randomx
# unprefixed, unless the compiler already namespaced it, it is a COMDAT, or it
# is one of the exemptions above.
LEAK=`defs "$OUT" | plain_globals \
      | grep -E 'randomx' \
      | grep -v "^$PREFIX" \
      | grep -v -F "$NS" \
      | grep -vE '^DW\.ref\.' \
      | grep -v -x -F -f "$COMDAT" \
      | head -5 || true`
if [ -n "$LEAK" ]; then
   echo "$0: these randomx-owned symbols were NOT prefixed in $OUT:" >&2
   echo "$LEAK" | sed 's/^/  /' >&2
   echo "  (a partial rename binds a variant entry point to stock internals," >&2
   echo "   which mines the wrong algorithm silently -- refusing to continue)" >&2
   exit 1
fi

# Same rule for the stubs, which the check above cannot see: a stub still
# named after an unprefixed target collides with the stock core's stub of the
# same name, and the linker keeps only one of them.
STUBLEAK=`defs "$OUT" | awk '{ print $1 }' \
          | grep -E '^\.refptr\.' \
          | sed 's/^\.refptr\.//' \
          | grep -E 'randomx' \
          | grep -v "^$PREFIX" \
          | grep -v -F "$NS" \
          | head -5 || true`
if [ -n "$STUBLEAK" ]; then
   echo "$0: these PE indirection stubs still name an unprefixed target:" >&2
   echo "$STUBLEAK" | sed 's/^/  .refptr./' >&2
   echo "  (the stock core defines a stub of the same name, so the linker" >&2
   echo "   keeps one and both cores read through it -- refusing to continue)" >&2
   exit 1
fi

rm -f "$ALL" "$OUT.keep" "$OUT.defs" "$COMDAT" "$MAP.names" "$OUT.refptr"
echo "  prefixed $COUNT symbols in `basename "$OUT"` with '$PREFIX'" \
     "(left $KEPT alone: COMDATs, std/compiler, already-namespaced)"
