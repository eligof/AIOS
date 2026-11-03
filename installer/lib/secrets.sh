# shellcheck shell=bash
# secrets.sh: the user's password hash for secrets/passwd/<user> (spec §4.1, §6.2 step 6).

# hash_password PASSWORD: print the yescrypt hash. Same call and check as `aios passwd`:
# mkpasswd -m yescrypt -s, with the password and a newline on stdin.
hash_password() {
    local hash
    if ! hash=$(printf '%s\n' "$1" | mkpasswd -m yescrypt -s); then
        log "error: mkpasswd -m yescrypt -s failed"
        return 1
    fi
    if [[ $hash != \$y\$* || $hash == *:* || $hash == *$'\n'* ]]; then
        log "error: mkpasswd -m yescrypt -s printed an unexpected hash"
        return 1
    fi
    printf '%s\n' "$hash"
}
