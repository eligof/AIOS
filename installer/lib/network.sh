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

# cachyos_mirror_url LIST: the cachyos repo database on the first https Server of LIST.
cachyos_mirror_url() {
    local line url
    while IFS= read -r line || [[ -n $line ]]; do
        if [[ $line =~ ^[[:space:]]*Server[[:space:]]*=[[:space:]]*(https://[^[:space:]]+) ]]; then
            url=${BASH_REMATCH[1]}
            url=${url//\$arch/x86_64}
            url=${url//\$repo/cachyos}
            printf '%s/cachyos.db\n' "${url%/}"
            return 0
        fi
    done 2>/dev/null <"$1"
    return 1
}

# check_network: Arch's mirror and the first CachyOS mirror both answer.
check_network() {
    local list=${AIOS_CACHYOS_MIRRORLIST:-/etc/pacman.d/cachyos-mirrorlist} url
    if ! probe "$AIOS_ARCH_MIRROR"; then
        log "error: no network: $AIOS_ARCH_MIRROR is unreachable (Wi-Fi: iwctl)"
        return 1
    fi
    if ! url=$(cachyos_mirror_url "$list"); then
        log "error: no https Server line in $list"
        return 1
    fi
    if ! probe "$url"; then
        log "error: the CachyOS mirror $url is unreachable (the first Server in $list)"
        return 1
    fi
}
