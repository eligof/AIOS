# shellcheck shell=bash
# config.sh: the install config and its validation (spec §6.2).
#
# Unattended configs are KEY=value lines. Blank lines and lines starting with "#" are
# ignored, and a trailing CR is dropped. The value is everything after the first "=",
# verbatim: no quotes, no expansion. The file is parsed with a whitelist and is never
# sourced or evaluated.
#
# Values that end up in commands, paths or the manifest (everything except the two
# secrets) must match a strict pattern, so they can never carry shell metacharacters,
# quotes or whitespace. Secrets may hold any printable character: they only ever reach a
# program on stdin.
#
# Environment overrides (tests only):
#   AIOS_FWCFG_DIR    qemu_fw_cfg sysfs dir  (default /sys/firmware/qemu_fw_cfg)
#   AIOS_ZONEINFO     time zone database     (default /usr/share/zoneinfo)
#   AIOS_PASSWD_FILE  accounts the live system already has (default /etc/passwd)

AIOS_CONFIG_KEYS=(DISK HOSTNAME USERNAME USER_PASSWORD LUKS_PASSPHRASE TIMEZONE WIPE EXTRA_CMDLINE)
AIOS_FWCFG_NAME=opt/aios/install.conf

# Kernel parameters AIOS sets itself. Keep in sync with RESERVED_CMDLINE_KEYS in
# aios-cli/crates/aios-manifest/src/validate.rs (a bats test compares the two).
AIOS_RESERVED_CMDLINE_KEYS=(root rootflags rw ro mount.usr mount.usrflags rd.luks.name aios.gen
    lockdown lsm init rdinit systemd.debug_shell rd.systemd.debug_shell apparmor security)

declare -gA CFG=()

is_config_key() {
    local k
    for k in "${AIOS_CONFIG_KEYS[@]}"; do
        [[ $1 == "$k" ]] && return 0
    done
    return 1
}

# parse_config FILE: fill CFG from FILE. Reports every problem, then returns 1 if any.
parse_config() {
    local file=$1 line key n=0 errors=0
    CFG=()
    if [[ ! -r $file ]]; then
        log "error: cannot read $file"
        return 1
    fi
    while IFS= read -r line || [[ -n $line ]]; do
        n=$((n + 1))
        line=${line%$'\r'}
        [[ -z $line || $line == \#* ]] && continue
        if [[ ! $line =~ ^([A-Z_]+)=(.*)$ ]]; then
            log "error: $file:$n: expected KEY=value"
            errors=$((errors + 1))
            continue
        fi
        key=${BASH_REMATCH[1]}
        if ! is_config_key "$key"; then
            log "error: $file:$n: unknown key $key"
            errors=$((errors + 1))
        elif [[ -v CFG[$key] ]]; then
            log "error: $file:$n: duplicate key $key"
            errors=$((errors + 1))
        else
            CFG[$key]=${BASH_REMATCH[2]}
        fi
    done <"$file"
    ((errors == 0))
}

valid_disk_path() {
    if [[ ! $1 =~ ^/dev/[A-Za-z0-9][A-Za-z0-9/_.:-]*$ || $1 == *..* ]]; then
        log "error: DISK must be a /dev path made of letters, digits and / _ . : - (got ${1@Q})"
        return 1
    fi
}

valid_hostname() {
    if [[ ! $1 =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]]; then
        log "error: HOSTNAME must be 1-63 lowercase letters, digits or -, not starting or ending with - (got ${1@Q})"
        return 1
    fi
}

# Same rule as the manifest's user names (aios-manifest valid_username).
valid_username_pattern() {
    if [[ ! $1 =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]; then
        log "error: USERNAME must start with a lowercase letter or _, then up to 31 lowercase letters, digits, _ or - (got ${1@Q})"
        return 1
    fi
}

# The user must not collide with an account the packages create (root, system users).
valid_username() {
    valid_username_pattern "$1" || return 1
    if [[ $1 == root || $1 == nobody ]] || grep -q "^$1:" "${AIOS_PASSWD_FILE:-/etc/passwd}"; then
        log "error: USERNAME $1 is a system account"
        return 1
    fi
}

valid_timezone_name() {
    if [[ ! $1 =~ ^[A-Za-z0-9_+-]+(/[A-Za-z0-9_+-]+)*$ ]]; then
        log "error: TIMEZONE must look like Region/City (got ${1@Q})"
        return 1
    fi
}

valid_timezone() {
    valid_timezone_name "$1" || return 1
    if [[ ! -f ${AIOS_ZONEINFO:-/usr/share/zoneinfo}/$1 ]]; then
        log "error: TIMEZONE $1 is not in ${AIOS_ZONEINFO:-/usr/share/zoneinfo}"
        return 1
    fi
}

# valid_secret NAME VALUE MINLEN: non-empty, at least MINLEN characters, no control characters.
valid_secret() {
    if ((${#2} < $3)); then
        log "error: $1 must be at least $3 characters"
        return 1
    fi
    if [[ $2 =~ [[:cntrl:]] ]]; then
        log "error: $1 must not contain control characters"
        return 1
    fi
}

is_reserved_cmdline_key() {
    local key=${1//-/_} r
    for r in "${AIOS_RESERVED_CMDLINE_KEYS[@]}"; do
        [[ $key == "${r//-/_}" ]] && return 0
    done
    return 1
}

# valid_extra_cmdline WORDS: space-separated kernel parameters the manifest may append.
valid_extra_cmdline() {
    local -a words
    local w
    read -ra words <<<"$1"
    for w in "${words[@]}"; do
        if [[ ! $w =~ ^[A-Za-z0-9._,:=/+@-]+$ ]]; then
            log "error: EXTRA_CMDLINE word ${w@Q} may only hold letters, digits and . _ , : = / + @ -"
            return 1
        fi
        if is_reserved_cmdline_key "${w%%=*}"; then
            log "error: EXTRA_CMDLINE word $w sets a parameter AIOS sets itself"
            return 1
        fi
    done
}

# validate_config UNATTENDED: apply defaults, then check every value. UNATTENDED=1 also
# requires WIPE=yes. Reports every problem, then returns 1 if any.
validate_config() {
    local unattended=$1 key errors=0
    : "${CFG[TIMEZONE]:=UTC}"
    : "${CFG[EXTRA_CMDLINE]:=}"
    : "${CFG[WIPE]:=}"
    for key in DISK HOSTNAME USERNAME USER_PASSWORD LUKS_PASSPHRASE; do
        if [[ -z ${CFG[$key]:-} ]]; then
            log "error: $key is missing"
            errors=$((errors + 1))
        fi
    done
    ((errors == 0)) || return 1
    valid_disk_path "${CFG[DISK]}" || errors=$((errors + 1))
    valid_hostname "${CFG[HOSTNAME]}" || errors=$((errors + 1))
    valid_username "${CFG[USERNAME]}" || errors=$((errors + 1))
    valid_timezone "${CFG[TIMEZONE]}" || errors=$((errors + 1))
    valid_extra_cmdline "${CFG[EXTRA_CMDLINE]}" || errors=$((errors + 1))
    valid_secret USER_PASSWORD "${CFG[USER_PASSWORD]}" 1 || errors=$((errors + 1))
    valid_secret LUKS_PASSPHRASE "${CFG[LUKS_PASSPHRASE]}" 8 || errors=$((errors + 1))
    if [[ $unattended == 1 && ${CFG[WIPE]} != yes ]]; then
        log "error: an unattended install erases DISK only with WIPE=yes"
        errors=$((errors + 1))
    fi
    ((errors == 0))
}

# fwcfg_config: print the QEMU fw_cfg install config path if the VM has one.
fwcfg_config() {
    local raw="${AIOS_FWCFG_DIR:-/sys/firmware/qemu_fw_cfg}/by_name/$AIOS_FWCFG_NAME/raw"
    if [[ -r $raw ]]; then
        printf '%s\n' "$raw"
    fi
}
