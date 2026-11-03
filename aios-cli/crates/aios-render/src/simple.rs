use aios_manifest::Manifest;

/// `/etc/hostname`.
pub fn hostname(m: &Manifest) -> String {
    format!("{}\n", m.system.hostname)
}

/// `/etc/locale.conf`.
pub fn locale_conf(m: &Manifest) -> String {
    format!("LANG={}\n", m.system.locale)
}

/// `/etc/locale.gen` for `locale-gen`. Empty for `C.UTF-8`, which glibc has built in.
pub fn locale_gen(m: &Manifest) -> String {
    let locale = &m.system.locale;
    if locale == "C.UTF-8" {
        String::new()
    } else if locale.ends_with(".UTF-8") {
        format!("{locale} UTF-8\n")
    } else {
        format!("{locale}\n")
    }
}

/// `/etc/vconsole.conf`.
pub fn vconsole_conf(m: &Manifest) -> String {
    format!("KEYMAP={}\n", m.system.keymap)
}

/// Target of the `/etc/localtime` symlink.
pub fn localtime_target(m: &Manifest) -> String {
    format!("/usr/share/zoneinfo/{}", m.system.timezone)
}

/// ESP `/loader/loader.conf`: the newest `cachyos` generation boots by default (spec §3 step 2).
pub fn loader_conf() -> String {
    "default aios-gen-*-cachyos*\ntimeout 3\neditor no\n".to_string()
}
