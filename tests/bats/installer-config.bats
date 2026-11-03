#!/usr/bin/env bats
# installer/lib/common.sh and config.sh: command wrappers, config parsing and validation
# (spec §6.2, §9).
# Literal $ and backticks in single quotes are test data; bats runs each test in a subshell.
# shellcheck disable=SC2016,SC2030,SC2031

setup() {
    LIB="$BATS_TEST_DIRNAME/../../installer/lib"
    # shellcheck source=/dev/null
    source "$LIB/common.sh"
    # shellcheck source=/dev/null
    source "$LIB/config.sh"
    CONF="$BATS_TEST_TMPDIR/install.conf"
    export AIOS_ZONEINFO="$BATS_TEST_TMPDIR/zoneinfo"
    mkdir -p "$AIOS_ZONEINFO/Asia"
    : >"$AIOS_ZONEINFO/UTC"
    : >"$AIOS_ZONEINFO/Asia/Jerusalem"
    export AIOS_PASSWD_FILE="$BATS_TEST_TMPDIR/passwd"
    printf '%s\n' 'root:x:0:0::/root:/bin/bash' 'alpm:x:946:946::/:/usr/bin/nologin' >"$AIOS_PASSWD_FILE"
    unset AIOS_INSTALL_DRYRUN AIOS_INSTALL_DRYRUN_FAILS
}

# good_config: a complete unattended config.
good_config() {
    cat >"$CONF" <<'EOF'
# e2e install config
DISK=/dev/vda
HOSTNAME=aios-e2e
USERNAME=tester
USER_PASSWORD=pa ss$;&|`x`
LUKS_PASSPHRASE=correct horse battery
TIMEZONE=Asia/Jerusalem
WIPE=yes
EXTRA_CMDLINE=console=ttyS0,115200 aios.test.fail_health=1
EOF
}

@test "run_cmd prints the quoted command in dry-run mode and runs nothing" {
    export AIOS_INSTALL_DRYRUN=1

    run run_cmd touch "$BATS_TEST_TMPDIR/a file"

    [ "$status" -eq 0 ]
    [ "$output" = "DRYRUN touch '$BATS_TEST_TMPDIR/a file'" ]
    [ ! -e "$BATS_TEST_TMPDIR/a file" ]
}

@test "run_cmd logs and runs the command otherwise" {
    run run_cmd touch "$BATS_TEST_TMPDIR/made"

    [ "$status" -eq 0 ]
    [ "$output" = "aios-install: + touch $BATS_TEST_TMPDIR/made" ]
    [ -f "$BATS_TEST_TMPDIR/made" ]
}

@test "run_stdin feeds the secret without a newline and never prints it" {
    run run_stdin 's3cret pass' sh -c 'cat >"$1"' _ "$BATS_TEST_TMPDIR/key"

    [ "$status" -eq 0 ]
    [ "$(od -An -c "$BATS_TEST_TMPDIR/key" | tr -s ' ')" = " s 3 c r e t p a s s" ]
    [[ "$output" != *s3cret* ]]

    export AIOS_INSTALL_DRYRUN=1
    run run_stdin 's3cret pass' cryptsetup open --key-file - /dev/vda2 aios
    [ "$output" = "DRYRUN cryptsetup open --key-file - /dev/vda2 aios <secret" ]
}

@test "run_write writes stdin with the mode, and only prints in dry-run mode" {
    printf 'hash\n' | run_write "$BATS_TEST_TMPDIR/secret" 0600

    [ "$(cat "$BATS_TEST_TMPDIR/secret")" = hash ]
    [ "$(stat -c %a "$BATS_TEST_TMPDIR/secret")" = 600 ]

    export AIOS_INSTALL_DRYRUN=1
    run run_write "$BATS_TEST_TMPDIR/other" 0644 <<<"content"
    [ "$output" = "DRYRUN write $BATS_TEST_TMPDIR/other 0644" ]
    [ ! -e "$BATS_TEST_TMPDIR/other" ]
}

@test "the dry-run failure hook fails exactly the listed command" {
    export AIOS_INSTALL_DRYRUN=1 AIOS_INSTALL_DRYRUN_FAILS="$BATS_TEST_TMPDIR/fails"
    echo "mkfs.btrfs -L aios /dev/mapper/aios" >"$AIOS_INSTALL_DRYRUN_FAILS"

    run run_cmd mkfs.btrfs -L aios /dev/mapper/aios
    [ "$status" -eq 1 ]
    run run_cmd mkfs.fat -F32 -n EFI /dev/vda1
    [ "$status" -eq 0 ]
}

@test "a complete config parses verbatim" {
    good_config

    parse_config "$CONF"

    [ "${CFG[DISK]}" = /dev/vda ]
    [ "${CFG[USER_PASSWORD]}" = 'pa ss$;&|`x`' ]
    [ "${CFG[LUKS_PASSPHRASE]}" = "correct horse battery" ]
    [ "${CFG[EXTRA_CMDLINE]}" = "console=ttyS0,115200 aios.test.fail_health=1" ]
    [ "${#CFG[@]}" -eq 8 ]
}

@test "comments, blank lines and CRLF line ends are accepted" {
    printf '# c\r\n\r\nDISK=/dev/vda\r\nHOSTNAME=h' >"$CONF"

    parse_config "$CONF"

    [ "${CFG[DISK]}" = /dev/vda ]
    [ "${CFG[HOSTNAME]}" = h ]
}

@test "unknown, malformed and duplicate keys are rejected with their line" {
    printf '%s\n' 'DISK=/dev/vda' 'ROOT_PASSWORD=x' 'hostname=h' ' DISK=/dev/sda' 'DISK=/dev/sdb' >"$CONF"

    run parse_config "$CONF"

    [ "$status" -eq 1 ]
    [[ "$output" == *"$CONF:2: unknown key ROOT_PASSWORD"* ]]
    [[ "$output" == *"$CONF:3: expected KEY=value"* ]]
    [[ "$output" == *"$CONF:4: expected KEY=value"* ]]
    [[ "$output" == *"$CONF:5: duplicate key DISK"* ]]
}

@test "the config is never executed or expanded" {
    cd "$BATS_TEST_TMPDIR"
    printf '%s\n' 'touch pwned1' 'HOSTNAME=$(touch pwned2)' 'DISK=`touch pwned3`' >"$CONF"

    run parse_config "$CONF"

    [ "$status" -eq 1 ]
    [ ! -e pwned1 ] && [ ! -e pwned2 ] && [ ! -e pwned3 ]
    parse_config <(printf 'HOSTNAME=$(touch pwned2)\n')
    [ "${CFG[HOSTNAME]}" = '$(touch pwned2)' ]
    [ ! -e pwned2 ]
}

@test "a complete config validates, with defaults for TIMEZONE and EXTRA_CMDLINE" {
    good_config
    parse_config "$CONF"
    validate_config 1

    grep -v -e '^TIMEZONE=' -e '^EXTRA_CMDLINE=' "$CONF" >"$CONF.min"
    parse_config "$CONF.min"
    validate_config 1
    [ "${CFG[TIMEZONE]}" = UTC ]
    [ "${CFG[EXTRA_CMDLINE]}" = "" ]
}

@test "missing required keys are all reported" {
    printf '%s\n' 'DISK=/dev/vda' 'WIPE=yes' >"$CONF"
    parse_config "$CONF"

    run validate_config 1

    [ "$status" -eq 1 ]
    [[ "$output" == *"HOSTNAME is missing"* ]]
    [[ "$output" == *"USERNAME is missing"* ]]
    [[ "$output" == *"USER_PASSWORD is missing"* ]]
    [[ "$output" == *"LUKS_PASSPHRASE is missing"* ]]
}

@test "shell metacharacters and whitespace are rejected in every non-secret value" {
    local key bad value
    for key in DISK HOSTNAME USERNAME TIMEZONE EXTRA_CMDLINE; do
        for bad in '$(id)' '`id`' 'a;b' 'a&b' 'a|b' 'a>b' "a'b" 'a"b' 'a\b' 'a*' 'a b'; do
            [ "$key" = EXTRA_CMDLINE ] && [ "$bad" = 'a b' ] && continue
            value=$bad
            [ "$key" = DISK ] && value="/dev/$bad"
            good_config
            grep -v "^$key=" "$CONF" >"$CONF.x"
            printf '%s=%s\n' "$key" "$value" >>"$CONF.x"
            parse_config "$CONF.x"
            run validate_config 1
            [ "$status" -eq 1 ] || { echo "accepted $key=$value"; return 1; }
        done
    done
}

@test "hostname and user name follow the manifest rules" {
    run valid_hostname nightcity
    [ "$status" -eq 0 ]
    for bad in NightCity -lead trail- "$(printf 'a%.0s' {1..64})" ""; do
        run valid_hostname "$bad"
        [ "$status" -eq 1 ]
    done

    run valid_username _svc-1
    [ "$status" -eq 0 ]
    for bad in Eli 1eli "$(printf 'a%.0s' {1..33})" root nobody alpm; do
        run valid_username "$bad"
        [ "$status" -eq 1 ]
    done
    [[ "$output" == *"USERNAME alpm is a system account"* ]]
}

@test "the time zone must exist in the zone database" {
    run valid_timezone Asia/Jerusalem
    [ "$status" -eq 0 ]
    run valid_timezone Mars/Olympus
    [ "$status" -eq 1 ]
    [[ "$output" == *"TIMEZONE Mars/Olympus is not in"* ]]
    run valid_timezone ../../etc/passwd
    [ "$status" -eq 1 ]
}

@test "secrets accept any printable text but no control characters, LUKS needs 8" {
    run valid_secret USER_PASSWORD 'x $;`|' 1
    [ "$status" -eq 0 ]
    run valid_secret USER_PASSWORD "$(printf 'a\tb')" 1
    [ "$status" -eq 1 ]
    run valid_secret LUKS_PASSPHRASE 1234567 8
    [ "$status" -eq 1 ]
    [[ "$output" == *"LUKS_PASSPHRASE must be at least 8 characters"* ]]
}

@test "EXTRA_CMDLINE refuses parameters AIOS sets itself" {
    run valid_extra_cmdline "console=ttyS0,115200 quiet aios.test.fail_health=1"
    [ "$status" -eq 0 ]
    for bad in root=/dev/sda rw aios.gen=0002 rd.luks.name=x systemd.debug-shell mount.usrflags=ro lsm=bpf; do
        run valid_extra_cmdline "quiet $bad"
        [ "$status" -eq 1 ]
        [[ "$output" == *"sets a parameter AIOS sets itself"* ]]
    done
}

@test "the reserved parameter list matches aios-manifest" {
    src="$BATS_TEST_DIRNAME/../../aios-cli/crates/aios-manifest/src/validate.rs"
    rust=$(sed -n '/^const RESERVED_CMDLINE_KEYS/,/^];/p' "$src" | grep -o '"[^"]*"' | tr -d '"' | sort)

    [ -n "$rust" ]
    [ "$(printf '%s\n' "${AIOS_RESERVED_CMDLINE_KEYS[@]}" | sort)" = "$rust" ]
}

@test "an unattended install needs WIPE=yes exactly" {
    for wipe in no YES "" "yes "; do
        good_config
        sed -i "s/^WIPE=.*/WIPE=$wipe/" "$CONF"
        parse_config "$CONF"
        run validate_config 1
        [ "$status" -eq 1 ]
        [[ "$output" == *"erases DISK only with WIPE=yes"* ]]
    done
    run validate_config 0
    [ "$status" -eq 0 ]
}

@test "the fw_cfg install config is found under sysfs" {
    export AIOS_FWCFG_DIR="$BATS_TEST_TMPDIR/fw_cfg"

    run fwcfg_config
    [ "$status" -eq 0 ]
    [ "$output" = "" ]

    mkdir -p "$AIOS_FWCFG_DIR/by_name/opt/aios/install.conf"
    good_config
    cp "$CONF" "$AIOS_FWCFG_DIR/by_name/opt/aios/install.conf/raw"
    run fwcfg_config
    [ "$output" = "$AIOS_FWCFG_DIR/by_name/opt/aios/install.conf/raw" ]
}
