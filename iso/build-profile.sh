#!/usr/bin/env bash
# build-profile.sh OUT REPO KEYS: assemble the archiso profile that mkarchiso builds (spec
# §6.1), without root. Run by `make iso-build`.
#   OUT   the profile to create (iso-build/). An existing OUT is replaced only if this
#         script made it (it holds the .aios-iso-build marker).
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
grep -Eqx 'AIOS_CACHYOS_KEYS="[0-9A-F]{40}( [0-9A-F]{40})*"' "$keys" 2>/dev/null ||
    fail "$keys pins no CachyOS key: run make keys"
if [[ -e $out || -L $out ]]; then
    [[ -f $out/$marker ]] || fail "$out exists but was not made by build-profile.sh; not touching it"
    rm -rf -- "$out"
fi

mkdir -p "$out"
cp -a "$here/profiledef.sh" "$here/packages.x86_64" "$here/efiboot" "$here/airootfs" "$out/"
sed "s|@AIOS_REPO@|$repo|" "$here/pacman.conf.in" >"$out/pacman.conf"
lib=$out/airootfs/usr/local/lib/aios-install
install -D -m 0755 "$root/installer/aios-install" "$out/airootfs/usr/local/bin/aios-install"
install -d -m 0755 "$lib"
install -m 0644 "$root"/installer/lib/*.sh "$lib/"
install -m 0644 "$keys" "$lib/keys.sh"
install -d -m 0755 "$out/airootfs/opt/aios-repo"
cp -a "$repo/." "$out/airootfs/opt/aios-repo/"
: >"$out/$marker"
echo "build-profile.sh: profile ready in $out (repo $repo)"
