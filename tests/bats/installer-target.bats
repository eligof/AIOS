#!/usr/bin/env bats
# installer/lib/{manifest,skeleton,secrets,usbguard,boot}.sh: what the installer writes to
# the target (spec §2, §4.1, §5.5, §6.2 steps 5, 6, 10-12, §9).
# Literal $ in single quotes is test data; bats runs each test in a subshell.
# shellcheck disable=SC2016,SC2030,SC2031

setup() {
    ROOT="$BATS_TEST_DIRNAME/../.."
    LIB="$ROOT/installer/lib"
    for f in common config manifest skeleton secrets usbguard boot; do
        # shellcheck source=/dev/null
        source "$LIB/$f.sh"
    done
    TEMPLATE="$ROOT/manifest/manifest.toml"
    BIN="$BATS_TEST_TMPDIR/bin"
    mkdir -p "$BIN"
    ln -s "$BATS_TEST_DIRNAME/fakes/installer" "$BIN/mkpasswd"
    PATH="$BIN:$PATH"
    export FAKE_SYS="$BATS_TEST_TMPDIR/sys" CALLS="$BATS_TEST_TMPDIR/calls"
    mkdir -p "$FAKE_SYS"
    : >"$CALLS"
    unset AIOS_INSTALL_DRYRUN
}

@test "EXTRA_CMDLINE becomes a TOML string-list body" {
    [ "$(toml_string_list "")" = "" ]
    [ "$(toml_string_list "console=ttyS0,115200")" = '"console=ttyS0,115200"' ]
    [ "$(toml_string_list "quiet  console=ttyS0,115200")" = '"quiet", "console=ttyS0,115200"' ]
}

@test "the default manifest is filled in exactly like the Rust default_manifest test" {
    run render_manifest aios-e2e tester UTC "console=ttyS0,115200" <"$TEMPLATE"

    [ "$status" -eq 0 ]
    expected=$(sed -e 's/@HOSTNAME@/aios-e2e/g' -e 's/@USERNAME@/tester/g' -e 's/@TIMEZONE@/UTC/g' \
        -e 's/@EXTRA_CMDLINE@/"console=ttyS0,115200"/g' "$TEMPLATE")
    [ "$output" = "$expected" ]
    [[ "$output" == *'hostname = "aios-e2e"'* ]]
    [[ "$output" == *'extra_cmdline = ["console=ttyS0,115200"]'* ]]
    [[ "$output" == *'[users.tester.home]'* ]]
    [[ ! "$output" =~ @[A-Z_]+@ ]]
}

@test "an empty EXTRA_CMDLINE renders an empty list, and the trailing newline is kept" {
    render_manifest h tester Asia/Jerusalem "" <"$TEMPLATE" >"$BATS_TEST_TMPDIR/m.toml"

    grep -q '^extra_cmdline = \[\] ' "$BATS_TEST_TMPDIR/m.toml"
    [ "$(tail -c 1 "$BATS_TEST_TMPDIR/m.toml" | od -An -c | tr -d ' ')" = '\n' ]
    [ "$(wc -l <"$BATS_TEST_TMPDIR/m.toml")" -eq "$(wc -l <"$TEMPLATE")" ]
}

@test "invalid values and unknown placeholders are refused" {
    run render_manifest NightCity tester UTC "" <"$TEMPLATE"
    [ "$status" -eq 1 ]
    run render_manifest h Tester UTC "" <"$TEMPLATE"
    [ "$status" -eq 1 ]
    run render_manifest h tester "../x" "" <"$TEMPLATE"
    [ "$status" -eq 1 ]
    run render_manifest h tester UTC "root=/dev/sda" <"$TEMPLATE"
    [ "$status" -eq 1 ]

    run render_manifest h tester UTC "" <<<'hostname = "@HOSTNAME@" # @ROOTPW@'
    [ "$status" -eq 1 ]
    [[ "$output" == *"unknown placeholder @ROOTPW@"* ]]
}

@test "after the rename, every home source the manifest names exists" {
    cp -r "$ROOT/manifest" "$BATS_TEST_TMPDIR/config"
    cfg="$BATS_TEST_TMPDIR/config"

    rename_home_template "$cfg" tester
    render_manifest h tester UTC "" <"$TEMPLATE" >"$cfg/manifest.toml"

    [ ! -e "$cfg/home/@USERNAME@" ]
    sources=$(sed -n 's/^"[^"]*" *= *"\(home\/[^"]*\)"$/\1/p' "$cfg/manifest.toml")
    [ "$(wc -l <<<"$sources")" -eq 19 ]
    while IFS= read -r src; do
        case $src in
            home/tester/*/) [ -d "$cfg/$src" ] || { echo "missing dir $src"; return 1; } ;;
            home/tester/*) [ -f "$cfg/$src" ] || { echo "missing file $src"; return 1; } ;;
            *) echo "source outside home/tester: $src"; return 1 ;;
        esac
    done <<<"$sources"
}

@test "the @blank skeleton has the spec's directories, modes and links" {
    blank="$BATS_TEST_TMPDIR/blank"
    mkdir "$blank"

    blank_skeleton "$blank" 2>/dev/null

    for d in usr etc persist home efi dev run var var/log var/lib var/cache; do
        [ "$(stat -c %a "$blank/$d")" = 755 ] || { echo "bad $d"; return 1; }
    done
    [ "$(stat -c %a "$blank/proc")" = 555 ]
    [ "$(stat -c %a "$blank/sys")" = 555 ]
    [ "$(stat -c %a "$blank/tmp")" = 1777 ]
    [ "$(stat -c %a "$blank/var/tmp")" = 1777 ]
    [ "$(stat -c %a "$blank/root")" = 750 ]
    [ "$(readlink "$blank/bin")" = usr/bin ]
    [ "$(readlink "$blank/sbin")" = usr/bin ]
    [ "$(readlink "$blank/lib")" = usr/lib ]
    [ "$(readlink "$blank/lib64")" = usr/lib ]
    [ "$(readlink "$blank/var/lib/pacman")" = ../../usr/lib/pacman ]
    [ "$(find "$blank" -mindepth 1 | wc -l)" -eq 21 ]
}

@test "the skeleton matches spec §2 word for word" {
    spec="$ROOT/docs/superpowers/specs/2026-11-03-base-iso-design.md"
    dirs=$(sed -n 's/^  - Top-level dirs: `\(.*\)`\.$/\1/p' "$spec" | tr ' ' '\n')
    links=$(grep -o '`[a-z0-9/][a-z0-9/]* → [a-z./][a-z./]*`' "$spec" | tr -d '`' | sed 's/ → / /' | sort)

    [ -n "$dirs" ]
    [ "$(skeleton_entries | awk '$1 == "dir" { print $3 }')" = "$dirs" ]
    [ "$(skeleton_entries | awk '$1 == "link" { print $3, $2 }' | sort)" = "$links" ]
}

@test "in dry-run mode the skeleton is one command per entry" {
    export AIOS_INSTALL_DRYRUN=1

    run blank_skeleton /mnt/aios-top/@blank

    [ "$status" -eq 0 ]
    [ "${#lines[@]}" -eq 21 ]
    [ "${lines[0]}" = "DRYRUN install -d -m 0755 /mnt/aios-top/@blank/usr" ]
    [ "${lines[9]}" = "DRYRUN install -d -m 1777 /mnt/aios-top/@blank/tmp" ]
    [ "${lines[20]}" = "DRYRUN ln -s ../../usr/lib/pacman /mnt/aios-top/@blank/var/lib/pacman" ]
}

@test "the password reaches mkpasswd on stdin and the yescrypt hash comes back" {
    run hash_password 'pa ss$;&|'

    [ "$status" -eq 0 ]
    [ "$output" = '$y$j9T$fakesalt$fakehashfakehashfakehashfakehashfake0' ]
    [ "$(cat "$CALLS")" = "mkpasswd -m yescrypt -s" ]
    [ "$(cat "$FAKE_SYS/mkpasswd.stdin")" = 'pa ss$;&|' ]
    [ "$(wc -l <"$FAKE_SYS/mkpasswd.stdin")" -eq 1 ]
}

@test "a failing mkpasswd or a hash that is not yescrypt is refused" {
    printf '#!/bin/sh\necho "\\$6\\$salt\\$sha512"\n' >"$BIN/mkpasswd.sha"
    chmod +x "$BIN/mkpasswd.sha"
    rm "$BIN/mkpasswd"
    ln -s "$BIN/mkpasswd.sha" "$BIN/mkpasswd"
    run hash_password x
    [ "$status" -eq 1 ]
    [[ "$output" == *"printed an unexpected hash"* ]]

    rm "$BIN/mkpasswd"
    ln -s /bin/false "$BIN/mkpasswd"
    run hash_password x
    [ "$status" -eq 1 ]
    [[ "$output" == *"mkpasswd -m yescrypt -s failed"* ]]
}

@test "USBGuard rules: present devices, then block new HID, then allow the rest" {
    policy='allow id 1d6b:0002 serial "0000:00:14.0" name "xHCI Host Controller" with-interface 09:00:00
allow id 046d:c52b serial "" name "USB Receiver" with-interface { 03:01:01 03:01:02 }'

    run usbguard_rules "$policy"

    [ "$status" -eq 0 ]
    [ "${#lines[@]}" -eq 8 ]
    [ "${lines[1]}" = 'allow id 1d6b:0002 serial "0000:00:14.0" name "xHCI Host Controller" with-interface 09:00:00' ]
    [ "${lines[2]}" = 'allow id 046d:c52b serial "" name "USB Receiver" with-interface { 03:01:01 03:01:02 }' ]
    [ "${lines[5]}" = "block with-interface one-of { 03:*:* }" ]
    [ "${lines[7]}" = "allow" ]
    [ "$(grep -vc '^#' <<<"$output")" -eq 4 ]
}

@test "USBGuard rules without present devices, and a policy that is not all allow rules" {
    run usbguard_rules ""
    [ "$status" -eq 0 ]
    [ "$(grep -v '^#' <<<"$output" | paste -sd'|')" = "block with-interface one-of { 03:*:* }|allow" ]

    run usbguard_rules 'block id 1234:5678'
    [ "$status" -eq 1 ]
    [[ "$output" == *"not an allow rule: block id 1234:5678"* ]]
}

@test "loader.conf matches aios_render::loader_conf" {
    rust=$(sed -n '/^pub fn loader_conf/,/^}/p' "$ROOT/aios-cli/crates/aios-render/src/simple.rs" |
        sed -n 's/^ *"\(.*\)"\.to_string()$/\1/p')

    [ -n "$rust" ]
    [ "$(loader_conf)" = "$(printf '%b' "$rust")" ]
}

@test "Setup Mode is read from sbctl status --json" {
    sbctl_setup_mode '{"installed":true,"guid":"x","setup_mode":true,"secure_boot":false,"vendors":[]}'
    sbctl_setup_mode '{ "setup_mode" : true }'
    run sbctl_setup_mode '{"installed":true,"setup_mode":false,"secure_boot":true}'
    [ "$status" -eq 1 ]
    run sbctl_setup_mode ''
    [ "$status" -eq 1 ]
}
