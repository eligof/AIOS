# shellcheck shell=bash
# keyring.sh: the CachyOS repository signing key (spec §6.2 step 9, Phase 3 contract 7).
# `aios bootstrap` runs pacstrap on the live system, which verifies packages with (and
# copies) the live pacman keyring. So before anything is erased, the installer checks that
# the live keyring trusts exactly the CachyOS keys pinned in keys.sh at ISO build time.
#
# Environment overrides (tests only):
#   AIOS_PACMAN_GNUPG  the pacman keyring (default /etc/pacman.d/gnupg)

AIOS_CACHYOS_UID=admin@cachyos.org

# trusted_key_fprs UID: fingerprints of the primary keys for UID that the pacman keyring
# trusts fully (validity f or u), one per line. Revoked, expired and untrusted keys and all
# subkeys are left out.
trusted_key_fprs() {
    {
        gpg --homedir "${AIOS_PACMAN_GNUPG:-/etc/pacman.d/gnupg}" --batch --no-permission-warning \
            --with-colons --list-keys -- "$1" 2>/dev/null || true
    } | awk -F: '
        $1 == "pub" { want = ($2 == "f" || $2 == "u"); next }
        $1 == "fpr" && want { print $10; want = 0; next }
        $1 == "sub" { want = 0 }
    '
}

# check_cachyos_keys PINNED: PINNED (space-separated fingerprints) must be exactly the set of
# CachyOS keys the live keyring trusts.
check_cachyos_keys() {
    local pinned live
    pinned=$(tr ' ' '\n' <<<"$1" | sed '/^$/d' | sort -u)
    if [[ -z $pinned ]]; then
        log "error: no pinned CachyOS key (keys.sh is empty)"
        return 1
    fi
    live=$(trusted_key_fprs "$AIOS_CACHYOS_UID" | sort -u)
    if [[ $live != "$pinned" ]]; then
        log "error: the live pacman keyring trusts the CachyOS keys [$(paste -sd' ' <<<"$live")]," \
            "but this ISO pinned [$(paste -sd' ' <<<"$pinned")]. Wait for pacman-init.service," \
            "or rebuild the ISO."
        return 1
    fi
}
