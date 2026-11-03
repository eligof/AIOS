# shellcheck shell=bash
# usbguard.sh: the USBGuard rule file (spec §5.5, §6.2 step 12). usbguard uses the first
# rule that matches, so: the devices present at install are allowed, then any new device
# with a HID interface (keyboard, mouse, BadUSB) is blocked, then everything else is allowed.

# usbguard_rules POLICY: rules.conf for POLICY, the output of `usbguard generate-policy`.
# Every POLICY line must be an allow rule.
usbguard_rules() {
    local line
    while IFS= read -r line; do
        if [[ -n $line && $line != "allow "* ]]; then
            log "error: usbguard generate-policy printed a rule that is not an allow rule: $line"
            return 1
        fi
    done <<<"$1"
    printf '%s\n' "# Written by aios-install (spec §5.5). Devices present at install:"
    if [[ -n $1 ]]; then
        printf '%s\n' "$1"
    fi
    printf '%s\n' "# New devices with a HID interface are blocked; approve one with" \
        "# run0 usbguard allow-device -p <id>." \
        "block with-interface one-of { 03:*:* }" \
        "# Every other new device is allowed." \
        "allow"
}
