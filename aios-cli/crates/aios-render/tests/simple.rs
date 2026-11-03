mod common;

use aios_render::{
    hostname, loader_conf, locale_conf, locale_gen, localtime_target, vconsole_conf,
};
use common::{manifest, manifest_from, MANIFEST};

#[test]
fn system_files() {
    let m = manifest();
    assert_eq!(hostname(&m), "nightcity\n");
    assert_eq!(locale_conf(&m), "LANG=en_US.UTF-8\n");
    assert_eq!(vconsole_conf(&m), "KEYMAP=us\n");
    assert_eq!(localtime_target(&m), "/usr/share/zoneinfo/Asia/Jerusalem");
}

#[test]
fn locale_gen_variants() {
    let with = |locale: &str| locale_gen(&manifest_from(&MANIFEST.replace("en_US.UTF-8", locale)));
    assert_eq!(with("en_US.UTF-8"), "en_US.UTF-8 UTF-8\n");
    assert_eq!(with("he_IL.UTF-8"), "he_IL.UTF-8 UTF-8\n");
    assert_eq!(with("C.UTF-8"), "");
    assert_eq!(with("en_US"), "en_US\n");
}

#[test]
fn loader_conf_boots_newest_cachyos_generation() {
    assert_eq!(
        loader_conf(),
        "default aios-gen-*-cachyos*\ntimeout 3\neditor no\n"
    );
}
