# shellcheck shell=bash
# common.sh: logging, step tracking and the command wrappers of aios-install (spec §6.2, §7).
#
# Every command that changes the disk or the live system goes through run_cmd, run_stdin
# or run_write. (It is not called "run": that would shadow bats' run in the tests.) With
# AIOS_INSTALL_DRYRUN=1 they print one "DRYRUN <command>" line on stdout and change
# nothing. Read-only queries (lsblk, sbctl status, mkpasswd, ...) always run.
#
# Test hook, dry-run only: a command whose DRYRUN text (without the "DRYRUN " prefix) is
# a line of the file $AIOS_INSTALL_DRYRUN_FAILS fails with status 1.

# The current step, for the failure message of on_exit (cleanup.sh).
# shellcheck disable=SC2034
AIOS_STEP=0
# shellcheck disable=SC2034
AIOS_STEP_NAME=start

# log MESSAGE: one line on stderr. A closed or unwritable stderr is not an error, so the
# exit trap's cleanup (cleanup.sh) still runs.
log() {
    printf 'aios-install: %s\n' "$*" >&2 || true
}

die() {
    log "error: $*"
    exit 1
}

# step N NAME: start step N of 13 (spec §6.2). A failure names the current step.
step() {
    # shellcheck disable=SC2034
    AIOS_STEP=$1
    # shellcheck disable=SC2034
    AIOS_STEP_NAME=$2
    log "step $1/13: $2"
}

dry_run() {
    [[ ${AIOS_INSTALL_DRYRUN:-0} == 1 ]]
}

# quote_cmd ARGS...: the command line as one string. Plain words stay as they are; any
# other argument is single-quoted (${arg@Q}), so the text is the same on every bash.
quote_cmd() {
    local out="" arg
    for arg in "$@"; do
        if [[ $arg =~ ^[A-Za-z0-9_./:=,@%+-]+$ ]]; then
            out+="${out:+ }$arg"
        else
            out+="${out:+ }${arg@Q}"
        fi
    done
    printf '%s' "$out"
}

# dry_print TEXT: print "DRYRUN TEXT"; fail if the test hook lists TEXT.
dry_print() {
    printf 'DRYRUN %s\n' "$1"
    if [[ -n ${AIOS_INSTALL_DRYRUN_FAILS:-} && -f $AIOS_INSTALL_DRYRUN_FAILS ]] &&
        grep -qxF -- "$1" "$AIOS_INSTALL_DRYRUN_FAILS"; then
        return 1
    fi
    return 0
}

# run_cmd CMD ARGS...: run a command that changes the system.
run_cmd() {
    local line
    line=$(quote_cmd "$@")
    if dry_run; then
        dry_print "$line"
        return
    fi
    log "+ $line"
    "$@"
}

# run_stdin DATA CMD ARGS...: like run_cmd, with DATA (a secret) on stdin, without a newline.
# DATA is never printed or logged.
run_stdin() {
    local data=$1 line
    shift
    line=$(quote_cmd "$@")
    if dry_run; then
        dry_print "$line <secret"
        return
    fi
    log "+ $line <secret"
    printf '%s' "$data" | "$@"
}

# run_write PATH [MODE]: write stdin to PATH, with MODE if given. The content is not logged.
run_write() {
    local path=$1 mode=${2:-}
    if dry_run; then
        cat >/dev/null
        dry_print "write $path${mode:+ $mode}"
        return
    fi
    log "+ write $path${mode:+ $mode}"
    if [[ -n $mode ]]; then
        install -m "$mode" /dev/stdin "$path"
    else
        cat >"$path"
    fi
}
