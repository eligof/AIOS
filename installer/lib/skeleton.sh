# shellcheck shell=bash
# skeleton.sh: the @blank root skeleton (spec §2), cloned to @root-live at every boot.

# skeleton_entries: one entry per line, "dir MODE PATH" or "link TARGET PATH", in creation
# order. The modes are those of Arch's filesystem package.
skeleton_entries() {
    cat <<'EOF'
dir 0755 usr
dir 0755 etc
dir 0755 persist
dir 0755 home
dir 0755 efi
dir 0555 proc
dir 0555 sys
dir 0755 dev
dir 0755 run
dir 1777 tmp
dir 0755 var
dir 0755 var/log
dir 0755 var/lib
dir 0755 var/cache
dir 1777 var/tmp
dir 0750 root
link usr/bin bin
link usr/bin sbin
link usr/lib lib
link usr/lib lib64
link ../../usr/lib/pacman var/lib/pacman
EOF
}

# blank_skeleton DIR: create the skeleton inside DIR (the new @blank subvolume).
blank_skeleton() {
    local kind arg path
    while read -r kind arg path; do
        case $kind in
            dir) run_cmd install -d -m "$arg" "$1/$path" ;;
            link) run_cmd ln -s "$arg" "$1/$path" ;;
        esac
    done < <(skeleton_entries)
}
