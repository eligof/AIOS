#!/usr/bin/env bats
# The Makefile's own rules, run in a scratch directory against fake commands: the ISO work
# directory cleanup (make iso, make clean-iso) and the pytest venv (make tools).
# shellcheck disable=SC2016

setup() {
    ROOT=$(readlink -f "$BATS_TEST_DIRNAME/../..")
    W=$BATS_TEST_TMPDIR/w
    FAKES=$BATS_TEST_TMPDIR/bin
    LOG=$BATS_TEST_TMPDIR/log
    mkdir -p "$W" "$FAKES"
    : >"$LOG"
}

# mk ARGS...: make with the repo's Makefile in $W, the fakes first on PATH, and none of the
# calling make's flags or variables (MAKEFLAGS carries command-line variables such as SUDO=).
mk() {
    env -u MAKEFLAGS -u MFLAGS -u MAKELEVEL -u SUDO -u PYTHON PATH="$FAKES:$PATH" \
        make --no-print-directory -f "$ROOT/Makefile" -C "$W" "$@"
}

# fake NAME [STATUS]: a command on PATH that logs its name and arguments and exits STATUS.
fake() {
    printf '#!/bin/sh\necho "%s $*" >>"%s"\nexit %s\n' "$1" "$LOG" "${2:-0}" >"$FAKES/$1"
    chmod +x "$FAKES/$1"
}

# has_hint [SUDO]: $output holds both lines make prints when rm cannot clear build/iso-work.
has_hint() {
    local line
    for line in 'If rm said "Device or resource busy", an interrupted build left mounts under build/iso-work.' \
        "Unmount them with \"${1:+$1 }umount -R MOUNTPOINT\" (findmnt lists them), then run make again."; do
        grep -Fxq -- "$line" <<<"$output" || { echo "no line: $line"; echo "$output"; return 1; }
    done
}

@test "make iso: sudo rm clears the work directory, or unshare rm with SUDO=; mkarchiso follows" {
    # -o iso-build: run only the iso recipe, not make keys and build-profile.sh.
    fake sudo
    run mk -o iso-build iso
    [ "$status" -eq 0 ] || { echo "$output"; return 1; }
    [ "$(cat "$LOG")" = "$(printf '%s\n' 'sudo rm -rf --one-file-system build/iso-work' \
        'sudo mkarchiso -v -w build/iso-work -o out iso-build/')" ]

    # Unprivileged mkarchiso leaves files owned by subordinate ids that only a user
    # namespace with them mapped can delete.
    : >"$LOG"
    fake unshare
    fake mkarchiso
    run mk -o iso-build iso SUDO=
    [ "$status" -eq 0 ] || { echo "$output"; return 1; }
    [ "$(cat "$LOG")" = "$(printf '%s\n' \
        'unshare --map-auto --map-root-user rm -rf --one-file-system build/iso-work' \
        'mkarchiso -v -w build/iso-work -o out iso-build/')" ]
}

@test "make iso and clean-iso: a failed work directory rm stops make with the umount -R hint" {
    fake sudo 1
    run mk -o iso-build iso
    [ "$status" -ne 0 ]
    [ "$(cat "$LOG")" = 'sudo rm -rf --one-file-system build/iso-work' ]
    has_hint sudo

    mkdir -p "$W/build/iso-work" "$W/iso-build"
    : >"$LOG"
    run mk clean-iso
    [ "$status" -ne 0 ]
    [ ! -e "$W/iso-build" ]
    [ "$(cat "$LOG")" = 'sudo rm -rf --one-file-system build/iso-work' ]
    has_hint sudo

    : >"$LOG"
    fake unshare 1
    run mk clean-iso SUDO=
    [ "$status" -ne 0 ]
    [ "$(cat "$LOG")" = 'unshare --map-auto --map-root-user rm -rf --one-file-system build/iso-work' ]
    has_hint
    [[ $output != *sudo* ]]

    : >"$LOG"
    fake unshare
    run mk clean-iso SUDO=
    [ "$status" -eq 0 ]
    [ "$(cat "$LOG")" = 'unshare --map-auto --map-root-user rm -rf --one-file-system build/iso-work' ]
    rmdir "$W/build/iso-work"
    run mk clean-iso SUDO=
    [ "$status" -eq 0 ]
    [ "$(wc -l <"$LOG")" -eq 1 ]
}

@test "the pytest venv is rebuilt from scratch when the Python minor version changes, only then" {
    # python: the version from $FAKE_VERSION; -m venv DIR makes DIR/bin/pip, which logs.
    cat >"$FAKES/python" <<'EOF'
#!/bin/sh
if [ "$1" = -c ] && [ "$2" = 'import sys;print(sys.version_info[:2])' ]; then
    cat "$FAKE_VERSION"
elif [ "$1" = -m ] && [ "$2" = venv ] && [ $# -eq 3 ]; then
    echo "venv $3" >>"$FAKE_LOG"
    mkdir -p "$3/bin"
    printf '#!/bin/sh\necho "pip $*" >>"$FAKE_LOG"\n' >"$3/bin/pip"
    chmod +x "$3/bin/pip"
else
    exit 1
fi
EOF
    chmod +x "$FAKES/python"
    export FAKE_LOG=$LOG FAKE_VERSION=$BATS_TEST_TMPDIR/version
    mkdir -p "$W/tests/e2e"
    : >"$W/tests/e2e/requirements.txt"
    pip='pip install -q --require-hashes --only-binary=:all: -r tests/e2e/requirements.txt'
    # Backdate everything make wrote, so the checks do not hang on timestamp granularity.
    backdate() { find "$W" -exec touch -h -d 2001-01-01 {} +; }

    echo '(3, 14)' >"$FAKE_VERSION"
    run mk build/venv/bin/pytest PYTHON="$FAKES/python"
    [ "$status" -eq 0 ] || { echo "$output"; return 1; }
    [ "$(cat "$LOG")" = "$(printf '%s\n' 'venv build/venv' "$pip")" ]
    [ -f "$W/build/venv/bin/pytest" ]

    backdate
    run mk build/venv/bin/pytest PYTHON="$FAKES/python"
    [ "$status" -eq 0 ] || { echo "$output"; return 1; }
    [ "$(wc -l <"$LOG")" -eq 2 ]

    # A new minor version: a fresh venv, without the old one's lib/python3.14.
    mkdir -p "$W/build/venv/lib/python3.14"
    backdate
    echo '(3, 15)' >"$FAKE_VERSION"
    run mk build/venv/bin/pytest PYTHON="$FAKES/python"
    [ "$status" -eq 0 ] || { echo "$output"; return 1; }
    [ "$(sed -n '3,$p' "$LOG")" = "$(printf '%s\n' 'venv build/venv' "$pip")" ]
    [ ! -e "$W/build/venv/lib/python3.14" ]
    [ -f "$W/build/venv/bin/pytest" ]

    backdate
    run mk build/venv/bin/pytest PYTHON="$FAKES/python"
    [ "$status" -eq 0 ]
    [ "$(wc -l <"$LOG")" -eq 4 ]
}
