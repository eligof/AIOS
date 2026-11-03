# shellcheck shell=bash
# manifest.sh: fill in the default manifest template (spec §6.2 step 6, Phase 4 Task 6).
# The template's placeholders are @HOSTNAME@, @USERNAME@, @TIMEZONE@ and @EXTRA_CMDLINE@
# (a TOML string-list body, possibly empty). Its home/@USERNAME@/ directory is renamed.

# toml_string_list WORDS: "a b" -> "a", "b". The words are validated kernel parameters,
# so they hold no quote or backslash to escape.
toml_string_list() {
    local -a words
    local out="" w
    read -ra words <<<"$1"
    for w in "${words[@]}"; do
        out+="${out:+, }\"$w\""
    done
    printf '%s' "$out"
}

# render_manifest HOSTNAME USERNAME TIMEZONE EXTRA_CMDLINE: the template on stdin, filled in,
# on stdout. Fails on an invalid value or a placeholder it does not know.
render_manifest() {
    local host=$1 user=$2 tz=$3 cmdline=$4 tpl list
    valid_hostname "$host" || return 1
    valid_username_pattern "$user" || return 1
    valid_timezone_name "$tz" || return 1
    valid_extra_cmdline "$cmdline" || return 1
    list=$(toml_string_list "$cmdline")
    tpl=$(
        cat
        printf x
    )
    tpl=${tpl%x}
    # bash 5.2+ would otherwise expand "&" in a replacement to the matched text.
    shopt -u patsub_replacement 2>/dev/null || true
    tpl=${tpl//@HOSTNAME@/"$host"}
    tpl=${tpl//@USERNAME@/"$user"}
    tpl=${tpl//@TIMEZONE@/"$tz"}
    tpl=${tpl//@EXTRA_CMDLINE@/"$list"}
    if [[ $tpl =~ @[A-Z_]+@ ]]; then
        log "error: manifest template: unknown placeholder ${BASH_REMATCH[0]}"
        return 1
    fi
    printf '%s' "$tpl"
}

# rename_home_template CONFIG USERNAME: CONFIG/home/@USERNAME@ -> CONFIG/home/USERNAME.
rename_home_template() {
    run_cmd mv "$1/home/@USERNAME@" "$1/home/$2"
}
