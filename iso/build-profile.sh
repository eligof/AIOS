#!/usr/bin/env bash
# build-profile.sh OUT REPO KEYS: assemble the archiso profile that mkarchiso builds (spec
# §6.1), without root. Run by `make iso-build`.
#   OUT   the profile to create (iso-build/). An existing OUT is replaced only if this
#         script made it: the .aios-iso-build marker, written right after mkdir, so a run
#         that fails midway leaves an OUT the next run replaces.
#   REPO  the local package repo (build/repo/ from `make repo`)
#   KEYS  the pinned CachyOS keys (installer/lib/keys.sh from `make keys`)
# OUT gets this profile (without pacman.conf.in and this script), pacman.conf with the
# absolute REPO path, the installer and its libraries, and a copy of REPO in /opt/aios-repo.
set -euo pipefail

here=$(dirname "$(readlink -f "$0")")
root=$(dirname "$here")
usage="usage: build-profile.sh OUT REPO KEYS"
out=${1:?$usage}
repo=${2:?$usage}
keys=${3:?$usage}
marker=.aios-iso-build

fail() {
    echo "build-profile.sh: $*" >&2
    exit 1
}

[[ -f $repo/aios-local.db.tar.gz ]] || fail "no $repo/aios-local.db.tar.gz: run make repo first"
repo=$(readlink -f "$repo")
[[ $repo =~ ^/[A-Za-z0-9._/+-]+$ ]] || fail "the repo path $repo has characters pacman.conf cannot hold"
# mkarchiso's pacstrap -c would otherwise use the host cache (see pacman.conf.in).
cache=$(dirname "$repo")/iso-pkgcache
# The installer sources KEYS as root, so take it only as make keys writes it: lines that
# start with # and exactly one assignment line.
LC_ALL=C grep -Eqx 'AIOS_CACHYOS_KEYS="[0-9A-F]{40}( [0-9A-F]{40})*"' "$keys" 2>/dev/null ||
    fail "$keys pins no CachyOS key: run make keys"
[[ $(LC_ALL=C grep -vc '^#' "$keys") == 1 ]] ||
    fail "$keys holds more than comments and one AIOS_CACHYOS_KEYS line: run make keys"
if [[ -e $out || -L $out ]]; then
    [[ -f $out/$marker ]] || fail "$out exists but was not made by build-profile.sh; not touching it"
    rm -rf -- "$out"
fi

mkdir -p "$out"
: >"$out/$marker"
cp -a "$here/profiledef.sh" "$here/packages.x86_64" "$here/efiboot" "$here/airootfs" "$out/"
mkdir -p "$cache"
sed -e "s|@AIOS_REPO@|$repo|" -e "s|@AIOS_CACHE@|$cache/|" "$here/pacman.conf.in" >"$out/pacman.conf"
lib=$out/airootfs/usr/local/lib/aios-install
install -D -m 0755 "$root/installer/aios-install" "$out/airootfs/usr/local/bin/aios-install"
install -d -m 0755 "$lib"
install -m 0644 "$root"/installer/lib/*.sh "$lib/"
install -m 0644 "$keys" "$lib/keys.sh"
install -d -m 0755 "$out/airootfs/opt/aios-repo"
cp -a "$repo/." "$out/airootfs/opt/aios-repo/"
echo "build-profile.sh: profile ready in $out (repo $repo)"
