#!/usr/bin/env bats
# Real pacman, without root, against the candidate roots bootstrap and apply install into
# (spec §4.3 steps 2 and 4). @blank holds bin, sbin, lib, lib64 and var/lib/pacman as
# symlinks, so pacstrap's empty database can't take `filesystem` and `pacman` over it.
# Bootstrap therefore pacstraps an empty root with DBPath in its /usr, and apply, whose
# database already owns those paths, keeps installing over a snapshot of @blank.
#
# Offline: the packages come from the pacman cache (/var/cache/pacman/pkg, or
# $AIOS_PKG_CACHE). Skips without pacman, an unprivileged user namespace or the packages.

setup() {
    PKG_CACHE=${AIOS_PKG_CACHE:-/var/cache/pacman/pkg}
    command -v pacman >/dev/null || skip "pacman is not installed"
    unshare -r true 2>/dev/null || skip "no unprivileged user namespace"
    FILESYSTEM=$(newest filesystem) || skip "no filesystem package in $PKG_CACHE"
    PACMAN=$(newest pacman) || skip "no pacman package in $PKG_CACHE"
    # Under $HOME rather than $BATS_TEST_TMPDIR: /tmp can be a small tmpfs.
    SCRATCH=$(mktemp -d "$HOME/.aios-pacstrap-layout.XXXXXX")
    printf '[options]\nSigLevel = Never\n' >"$SCRATCH/pacman.conf"
}

teardown() {
    if [ -n "${SCRATCH:-}" ]; then
        rm -rf -- "$SCRATCH"
    fi
}

# newest NAME: the newest NAME-<version>-<release>-<arch> package in the cache.
newest() {
    local file
    file=$(find "$PKG_CACHE" -maxdepth 1 -type f -regextype posix-extended \
        -regex ".*/$1-[^-]+-[^-]+-[^-]+\.pkg\.tar\.(zst|xz)" -printf '%f\n' 2>/dev/null |
        sort -V | tail -n 1)
    [ -n "$file" ] && printf '%s\n' "$PKG_CACHE/$file"
}

# blank ROOT: the @blank skeleton (spec §2) plus the candidate's mount points (step 3).
blank() {
    mkdir -p "$1"
    (
        cd "$1" || exit 1
        mkdir -p usr etc persist home efi proc sys dev run tmp var/log var/lib var/cache var/tmp \
            root usr/lib/pacman etc/pacman.d/hooks var/cache/pacman/pkg persist/aios/repo
        ln -s usr/bin bin
        ln -s usr/bin sbin
        ln -s usr/lib lib
        ln -s usr/lib lib64
        ln -s ../../usr/lib/pacman var/lib/pacman
    )
}

# empty ROOT: bootstrap's empty @root-cand with the candidate's mount points.
empty() {
    mkdir -p "$1"/{usr/lib/pacman,etc/pacman.d/hooks,var/log,var/cache/pacman/pkg,persist/aios/repo}
}

# install ROOT [PACMAN_ARGS...]: install both packages the way pacstrap's pacman would,
# without hooks or install scriptlets (they would run programs in ROOT).
install_into() {
    local root=$1
    shift
    run unshare -r pacman --root "$root" --config "$SCRATCH/pacman.conf" \
        --hookdir "$root/etc/pacman.d/hooks" --cachedir "$root/var/cache/pacman/pkg" \
        --noscriptlet --noconfirm -dd "$@" -U "$FILESYSTEM" "$PACMAN"
}

# pacstrap_into ROOT [ARGS...]: the real pacstrap as a regular user (-N), with the config
# bootstrap writes (DBPath and HookDir in ROOT), installing both packages from their files.
# ARGS go after the root, where bootstrap puts its --dbpath.
pacstrap_into() {
    local root=$1
    shift
    command -v pacstrap >/dev/null || skip "pacstrap is not installed"
    printf '[options]\nDBPath = %s/usr/lib/pacman/\nHookDir = %s/etc/pacman.d/hooks/\nSigLevel = Never\n' \
        "$root" "$root" >"$SCRATCH/pacstrap.conf"
    run pacstrap -N -U -D -G -M -C "$SCRATCH/pacstrap.conf" "$root" "$@" --noscriptlet \
        "$FILESYSTEM" "$PACMAN"
}

# installed ROOT NAME: the database in ROOT/usr/lib/pacman holds package NAME.
installed() {
    compgen -G "$1/usr/lib/pacman/local/$2-[0-9]*" >/dev/null
}

@test "an empty database can't install filesystem and pacman over @blank's symlinks" {
    blank "$SCRATCH/root"
    # The old pacstrap config: no DBPath, so the database went through var/lib/pacman.
    install_into "$SCRATCH/root"
    [ "$status" -ne 0 ]
    [[ "$output" == *"filesystem: $SCRATCH/root/bin exists in filesystem"* ]]
    [[ "$output" == *"pacman: $SCRATCH/root/var/lib/pacman exists in filesystem"* ]]
    run installed "$SCRATCH/root" filesystem
    [ "$status" -ne 0 ]
}

@test "an empty root with DBPath in /usr takes both packages" {
    empty "$SCRATCH/root"
    install_into "$SCRATCH/root" --dbpath "$SCRATCH/root/usr/lib/pacman/"
    [ "$status" -eq 0 ]
    installed "$SCRATCH/root" filesystem
    installed "$SCRATCH/root" pacman
    [ "$(readlink "$SCRATCH/root/bin")" = usr/bin ]
}

@test "with the database owning them, @blank's symlinks are no conflict" {
    empty "$SCRATCH/gen"
    install_into "$SCRATCH/gen" --dbpath "$SCRATCH/gen/usr/lib/pacman/"
    [ "$status" -eq 0 ]
    # Apply: a snapshot of @blank as the root, the generation's /usr (here its database).
    blank "$SCRATCH/root"
    cp -a "$SCRATCH/gen/usr/lib/pacman/." "$SCRATCH/root/usr/lib/pacman/"
    install_into "$SCRATCH/root" --dbpath "$SCRATCH/root/usr/lib/pacman/"
    [ "$status" -eq 0 ]
    [[ "$output" != *"exists in filesystem"* ]]
    # pacman may replace the root's var/lib/pacman link with a directory; harmless, since
    # DBPath points into /usr and every boot starts from @blank's link again.
    [ "$(readlink "$SCRATCH/root/bin")" = usr/bin ]
}

@test "pacstrap ignores the config's DBPath: its own -b puts the database in var/lib/pacman" {
    empty "$SCRATCH/root"
    pacstrap_into "$SCRATCH/root"
    [ "$status" -eq 0 ]
    run installed "$SCRATCH/root" filesystem
    [ "$status" -ne 0 ]
    compgen -G "$SCRATCH/root/var/lib/pacman/local/filesystem-[0-9]*" >/dev/null
}

@test "pacstrap with bootstrap's --dbpath puts the database in the root's /usr" {
    empty "$SCRATCH/root"
    pacstrap_into "$SCRATCH/root" --dbpath="$SCRATCH/root/usr/lib/pacman/"
    [ "$status" -eq 0 ]
    installed "$SCRATCH/root" filesystem
    installed "$SCRATCH/root" pacman
    run compgen -G "$SCRATCH/root/var/lib/pacman/local/*"
    [ "$status" -ne 0 ]
}
