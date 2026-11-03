# shellcheck shell=bash
# cleanup.sh: undo the live-system state on exit (spec §7): unmount what this run mounted,
# newest first, then close the LUKS mapping. The disk itself is left as it is; the user
# runs the installer again.

AIOS_MOUNTS=()
AIOS_LUKS_OPEN=0

# mount_tracked MOUNT-ARGS... TARGET: mount, and remember TARGET (the last argument).
mount_tracked() {
    run_cmd mount "$@"
    AIOS_MOUNTS+=("${!#}")
}

# luks_opened: the "aios" mapping is open from now on.
luks_opened() {
    AIOS_LUKS_OPEN=1
}

# cleanup: unmount and close everything. Never fails; problems are warnings.
cleanup() {
    local i target
    for ((i = ${#AIOS_MOUNTS[@]} - 1; i >= 0; i--)); do
        target=${AIOS_MOUNTS[i]}
        run_cmd umount "$target" || run_cmd umount -l "$target" ||
            log "warning: could not unmount $target"
    done
    AIOS_MOUNTS=()
    if ((AIOS_LUKS_OPEN)); then
        run_cmd cryptsetup close aios || log "warning: could not close the LUKS mapping aios"
        AIOS_LUKS_OPEN=0
    fi
}

# on_exit: the EXIT trap. On failure: name the step, clean up, keep the exit status.
on_exit() {
    local rc=$?
    trap - EXIT
    if ((rc != 0)); then
        log "step $AIOS_STEP ($AIOS_STEP_NAME) failed (exit $rc)"
        cleanup
        log "the disk is left in an undefined state: fix the problem and run aios-install again"
    fi
    exit "$rc"
}
