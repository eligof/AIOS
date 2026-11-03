# shellcheck shell=bash
# cpu.sh: x86-64-v3 detection and the v3 parts of pacman.conf (spec §6.2 step 1).
#
# Environment overrides (tests only):
#   AIOS_LDSO  the dynamic loader (default /lib/ld-linux-x86-64.so.2)

# cpu_supports_v3: true if glibc's loader lists x86-64-v3 as supported. Its --help ends with
#   Subdirectories of glibc-hwcaps directories, in priority order:
#     x86-64-v4
#     x86-64-v3 (supported, searched)
cpu_supports_v3() {
    local out
    out=$("${AIOS_LDSO:-/lib/ld-linux-x86-64.so.2}" --help 2>/dev/null) || return 1
    grep -qE '^[[:space:]]*x86-64-v3 \(supported(, searched)?\)[[:space:]]*$' <<<"$out"
}

# strip_v3: copy pacman.conf from stdin to stdout without its "# BEGIN v3" ... "# END v3"
# regions (the v3 Architecture line and the CachyOS v3 repos). Unbalanced markers fail.
strip_v3() {
    awk '
        /^# BEGIN v3$/ {
            if (inside) { printf "strip_v3: line %d: nested # BEGIN v3\n", NR > "/dev/stderr"; bad = 1; exit 1 }
            inside = 1; next
        }
        /^# END v3$/ {
            if (!inside) { printf "strip_v3: line %d: # END v3 without # BEGIN v3\n", NR > "/dev/stderr"; bad = 1; exit 1 }
            inside = 0; next
        }
        !inside { print }
        END {
            if (inside && !bad) { print "strip_v3: # BEGIN v3 is never closed" > "/dev/stderr"; exit 1 }
        }
    '
}
