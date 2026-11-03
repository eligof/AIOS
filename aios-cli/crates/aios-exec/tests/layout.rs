use aios_exec::Layout;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

#[test]
fn defaults_follow_the_spec() {
    let l = Layout::from_vars(|_| None);
    let expected = [
        (&l.top, "/run/aios/top"),
        (&l.cand, "/run/aios/cand"),
        (&l.esp, "/efi"),
        (&l.config, "/persist/aios/config"),
        (&l.secrets, "/persist/aios/secrets"),
        (&l.persist, "/persist"),
        (&l.home, "/home"),
        (&l.log, "/var/log"),
        (&l.live_etc, "/etc"),
        (&l.proc_cmdline, "/proc/cmdline"),
        (&l.efivars, "/sys/firmware/efi/efivars"),
        (&l.lock, "/run/aios.lock"),
        (&l.device, "/dev/mapper/aios"),
    ];
    for (field, path) in expected {
        assert_eq!(field, Path::new(path));
    }
}

#[test]
fn every_path_has_an_env_override() {
    let names = [
        "AIOS_TOP",
        "AIOS_CAND",
        "AIOS_ESP",
        "AIOS_CONFIG",
        "AIOS_SECRETS",
        "AIOS_PERSIST",
        "AIOS_HOME",
        "AIOS_LOG",
        "AIOS_LIVE_ETC",
        "AIOS_CMDLINE",
        "AIOS_EFIVARS",
        "AIOS_LOCK",
        "AIOS_DEVICE",
    ];
    let vars: BTreeMap<&str, OsString> = names
        .iter()
        .map(|n| (*n, OsString::from(format!("/t/{n}"))))
        .collect();
    let l = Layout::from_vars(|name| vars.get(name).cloned());
    let fields = [
        &l.top,
        &l.cand,
        &l.esp,
        &l.config,
        &l.secrets,
        &l.persist,
        &l.home,
        &l.log,
        &l.live_etc,
        &l.proc_cmdline,
        &l.efivars,
        &l.lock,
        &l.device,
    ];
    for (name, field) in names.iter().zip(fields) {
        assert_eq!(field, &PathBuf::from(format!("/t/{name}")));
    }
}

#[test]
fn under_puts_everything_below_one_root() {
    let l = Layout::under(Path::new("/tmp/x"));
    assert_eq!(l.top, Path::new("/tmp/x/top"));
    assert_eq!(l.live_etc, Path::new("/tmp/x/live-etc"));
    assert_eq!(l.proc_cmdline, Path::new("/tmp/x/cmdline"));
    assert_eq!(l.lock, Path::new("/tmp/x/aios.lock"));
    assert_eq!(l.device, Path::new("/dev/mapper/aios"));
}

#[test]
fn derived_paths() {
    let l = Layout::from_vars(|_| None);
    assert_eq!(
        l.manifest_path(),
        Path::new("/persist/aios/config/manifest.toml")
    );
    assert_eq!(
        l.subvol("@usr-gen-0007"),
        Path::new("/run/aios/top/@usr-gen-0007")
    );
    assert_eq!(l.uki_dir(), Path::new("/efi/EFI/Linux"));
    assert_eq!(
        l.loader_entry_default(),
        Path::new(
            "/sys/firmware/efi/efivars/LoaderEntryDefault-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f"
        )
    );
    assert_eq!(l.repo(), Path::new("/persist/aios/repo"));
    assert_eq!(l.pkg_cache(), Path::new("/persist/var/cache/pacman/pkg"));
    assert_eq!(
        l.passwd_secret("eli"),
        Path::new("/persist/aios/secrets/passwd/eli")
    );
}

#[test]
fn persist_path_maps_onto_the_persist_field() {
    let l = Layout::under(Path::new("/t"));
    assert_eq!(l.persist_path("/persist"), Path::new("/t/persist/"));
    assert_eq!(
        l.persist_path("/persist/var/lib/NetworkManager"),
        Path::new("/t/persist/var/lib/NetworkManager")
    );
}

#[test]
fn readers_mount_at_ro_pid_next_to_top() {
    let pid = std::process::id();
    assert_eq!(
        Layout::from_vars(|_| None).ro_top(),
        PathBuf::from(format!("/run/aios/ro.{pid}"))
    );
    assert_eq!(
        Layout::under(Path::new("/t")).ro_top(),
        PathBuf::from(format!("/t/ro.{pid}"))
    );
}
