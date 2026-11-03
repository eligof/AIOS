# shellcheck shell=bash
# network.sh: the network check of the preflight (spec §6.2 step 1). The bootstrap's pacstrap
# downloads from Arch's mirrors and from CachyOS's, so one of each must answer.
#
# Environment overrides (tests only):
#   AIOS_CACHYOS_MIRRORLIST  the CachyOS mirrorlist (default /etc/pacman.d/cachyos-mirrorlist)

AIOS_ARCH_MIRROR=https://geo.mirror.pkgbuild.com

# probe URL: a HEAD request that must succeed; with -f an HTTP error fails too.
probe() {
    curl -fsI --max-time 20 --retry 3 --retry-connrefused "$1" >/dev/null
}

# cachyos_mirror_urls LIST: the cachyos repo database on each of the first 3 https Servers of
# LIST, one per line. Fails if there is none.
cachyos_mirror_urls() {
    local line url n=0
    while ((n < 3)) && { IFS= read -r line || [[ -n $line ]]; }; do
        if [[ $line =~ ^[[:space:]]*Server[[:space:]]*=[[:space:]]*(https://[^[:space:]]+) ]]; then
            url=${BASH_REMATCH[1]}
            url=${url//\$arch/x86_64}
            url=${url//\$repo/cachyos}
            printf '%s/cachyos.db\n' "${url%/}"
            n=$((n + 1))
        fi
    done 2>/dev/null <"$1"
    ((n > 0))
}

# check_network: Arch's mirror answers, and so does at least one of the first 3 https CachyOS
# mirrors (one dead mirror at the top of the list must not fail an install).
check_network() {
    local list=${AIOS_CACHYOS_MIRRORLIST:-/etc/pacman.d/cachyos-mirrorlist} url urls=() n=0
    if ! probe "$AIOS_ARCH_MIRROR"; then
        log "error: no network: $AIOS_ARCH_MIRROR is unreachable (Wi-Fi: iwctl)"
        return 1
    fi
    if ! mapfile -t urls < <(cachyos_mirror_urls "$list") || ((${#urls[@]} == 0)); then
        log "error: no https Server line in $list"
        return 1
    fi
    for url in "${urls[@]}"; do
        n=$((n + 1))
        if probe "$url"; then
            return 0
        fi
    done
    log "error: no CachyOS mirror answered (tried the first $n https Servers in $list)"
    return 1
}
