use aios_exec::{
    days_since_epoch, luks_uuid_from_cmdline, parse_df_avail, parse_efivar_utf16, rfc3339_utc,
    sha256_hex, unit_file_name,
};
use std::time::{Duration, UNIX_EPOCH};

const UUID: &str = "0b6c2e7f-5d0a-4c2e-9a71-3f1d2c4b5a69";

#[test]
fn luks_uuid_comes_from_rd_luks_name() {
    let cmdline = format!("rd.luks.name={UUID}=aios root=/dev/mapper/aios quiet");
    assert_eq!(luks_uuid_from_cmdline(&cmdline).as_deref(), Some(UUID));
    let other = format!("rd.luks.name=1111=swap rd.luks.name={UUID}=aios");
    assert_eq!(luks_uuid_from_cmdline(&other).as_deref(), Some(UUID));
    assert_eq!(luks_uuid_from_cmdline("root=/dev/sda2 quiet"), None);
    assert_eq!(luks_uuid_from_cmdline("rd.luks.name==aios"), None);
}

#[test]
fn conflicting_luks_tokens_are_none() {
    let same = format!("rd.luks.name={UUID}=aios rd.luks.name={UUID}=aios");
    assert_eq!(luks_uuid_from_cmdline(&same).as_deref(), Some(UUID));
    let conflict = format!("rd.luks.name={UUID}=aios rd.luks.name=2222=aios");
    assert_eq!(luks_uuid_from_cmdline(&conflict), None);
}

#[test]
fn days_and_timestamps_in_utc() {
    let t = UNIX_EPOCH + Duration::from_secs(1_793_740_445);
    assert_eq!(days_since_epoch(t), 20760);
    assert_eq!(rfc3339_utc(t), "2026-11-03T21:14:05Z");
    assert_eq!(rfc3339_utc(UNIX_EPOCH), "1970-01-01T00:00:00Z");
    assert_eq!(days_since_epoch(UNIX_EPOCH - Duration::from_secs(5)), 0);
}

#[test]
fn calendar_edges() {
    let at = |secs: u64| rfc3339_utc(UNIX_EPOCH + Duration::from_secs(secs));
    assert_eq!(at(951_782_400), "2000-02-29T00:00:00Z");
    assert_eq!(at(1_709_251_199), "2024-02-29T23:59:59Z");
    assert_eq!(at(946_684_799), "1999-12-31T23:59:59Z");
}

#[test]
fn sha256_is_lowercase_hex() {
    assert_eq!(
        sha256_hex(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        sha256_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn efivar_strings_skip_attributes_and_the_nul() {
    let mut bytes = vec![0x07, 0, 0, 0];
    for unit in "aios-gen-0007-cachyos.efi\0".encode_utf16() {
        bytes.extend(unit.to_le_bytes());
    }
    assert_eq!(
        parse_efivar_utf16(&bytes).as_deref(),
        Some("aios-gen-0007-cachyos.efi")
    );
    assert_eq!(parse_efivar_utf16(&[7, 0, 0]), None);
    assert_eq!(parse_efivar_utf16(&[7, 0, 0, 0, 0, 0]), None);
    assert_eq!(parse_efivar_utf16(&[7, 0, 0, 0, b'a']), None);
}

#[test]
fn df_avail_is_the_last_number() {
    assert_eq!(
        parse_df_avail("     Avail\n2040123392\n"),
        Some(2_040_123_392)
    );
    assert_eq!(parse_df_avail("Avail\n"), None);
    assert_eq!(parse_df_avail(""), None);
}

#[test]
fn unit_names_get_a_service_suffix() {
    assert_eq!(unit_file_name("NetworkManager"), "NetworkManager.service");
    assert_eq!(unit_file_name("fwupd-refresh.timer"), "fwupd-refresh.timer");
}
