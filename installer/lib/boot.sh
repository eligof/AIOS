# shellcheck shell=bash
# boot.sh: the ESP loader.conf and the Secure Boot setup-mode check (spec §6.2 steps 10-11).

# loader_conf: the ESP /loader/loader.conf. Same text as aios_render::loader_conf()
# (a bats test compares the two): the newest cachyos generation boots by default.
loader_conf() {
    printf '%s\n' 'default aios-gen-*-cachyos*' 'timeout 3' 'editor no'
}

# sbctl_setup_mode JSON: true if `sbctl status --json` reports Setup Mode.
sbctl_setup_mode() {
    [[ $1 =~ \"setup_mode\"[[:space:]]*:[[:space:]]*true ]]
}
