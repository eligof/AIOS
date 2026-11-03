# shellcheck shell=bash
# cleanup.sh: undo the live-system state on exit (spec §7): unmount what this run mounted,
# newest first, then anything else still mounted from the LUKS mapping, deepest first, then
# close the mapping. The disk itself is left as it is; the user runs the installer again.
#
# A mount or the LUKS open is tracked before its command runs, so an interrupt in between
# is still cleaned up. Cleanup then only touches what really is mounted or open (in dry-run
# mode, where nothing is, it acts as if everything tracked were). Nothing in it can fail:
# every command is guarded, and problems are warnings.
#
# Environment overrides (tests only):
#   AIOS_MAPPER_DIR  where device-mapper nodes appear (default /dev/mapper)

AIOS_MOUNTS=()
AIOS_LUKS_OPEN=0
# 1 once step 3 starts changing the disk; before that a failure changed nothing on it.
AIOS_DISK_CHANGED=0
# 1 once step 13 has unmounted the finished install; a failure after that leaves AIOS installed.
AIOS_INSTALLED=0
AIOS_LUKS_DEV=/dev/mapper/aios

# mount_tracked MOUNT-ARGS... TARGET: remember TARGET (the last argument), then mount.
mount_tracked() {
    AIOS_MOUNTS+=("${!#}")
    run_cmd mount "$@"
}

# luks_open_tracked PASSPHRASE DEVICE: remember the "aios" mapping, then open DEVICE as it.
luks_open_tracked() {
    AIOS_LUKS_OPEN=1
    run_stdin "$1" cryptsetup open --key-file - "$2" aios
}

# luks_is_open: /dev/mapper/aios exists.
luks_is_open() {
    [[ -e ${AIOS_MAPPER_DIR:-/dev/mapper}/aios ]]
}

# is_mounted PATH: PATH is a mount point. Always true in dry-run mode.
is_mounted() {
    dry_run || mountpoint -q -- "$1"
}

# mapper_mounts: the mount points of /dev/mapper/aios (btrfs subvolumes included), deepest
# first, as findmnt -r prints them (\x-escaped, so one word each).
mapper_mounts() {
    { findmnt -rno TARGET -S "$AIOS_LUKS_DEV" 2>/dev/null || true; } |
        awk -F/ '{ print NF, $0 }' | sort -s -rn -k1,1 | cut -d' ' -f2-
}

# unmount_tree TARGET: unmount TARGET and everything below it; lazily if it is busy.
unmount_tree() {
    run_cmd umount -R "$1" || run_cmd umount -R -l "$1" || log "warning: could not unmount $1"
}

# cleanup: unmount and close everything. Never fails.
cleanup() {
    local i target raw
    for ((i = ${#AIOS_MOUNTS[@]} - 1; i >= 0; i--)); do
        target=${AIOS_MOUNTS[i]}
        if is_mounted "$target"; then
            unmount_tree "$target"
        fi
    done
    AIOS_MOUNTS=()
    if ((AIOS_LUKS_OPEN)); then
        if dry_run || luks_is_open; then
            while IFS= read -r raw; do
                printf -v target '%b' "$raw" || continue
                if is_mounted "$target"; then
                    unmount_tree "$target"
                fi
            done < <(mapper_mounts)
            run_cmd cryptsetup close aios || log "warning: could not close the LUKS mapping aios"
        fi
        AIOS_LUKS_OPEN=0
    fi
}

# on_exit: the EXIT trap. On failure: name the step, clean up, keep the exit status. It runs
# without errexit and ignores further interrupts, hangups and SIGPIPE (stderr may be a dead pipe), so
# nothing stops the cleanup half way.
on_exit() {
    local rc=$?
    set +e
    trap '' INT TERM HUP PIPE
    trap - EXIT
    if ((rc != 0)); then
        log "step $AIOS_STEP ($AIOS_STEP_NAME) failed (exit $rc)"
        cleanup
        if ((AIOS_INSTALLED)); then
            log "AIOS is installed on the disk; only the end of step 13 failed: reboot by hand"
        elif ((AIOS_DISK_CHANGED)); then
            log "the disk is left in an undefined state: fix the problem and run aios-install again"
        else
            log "nothing on the disk was changed: fix the problem and run aios-install again"
        fi
    fi
    exit "$rc"
}
