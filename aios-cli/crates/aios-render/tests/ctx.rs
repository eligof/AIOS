mod common;

use aios_gen::GenId;
use aios_render::RenderCtx;
use common::{ctx, HARDENING};

const LUKS: &str = "0b6c2e7f-5d0a-4c2e-9a71-3f1d2c4b5a69";
const ESP: &str = "7A1B-2C3D";

#[test]
fn new_accepts_the_fixture_values() {
    assert_eq!(RenderCtx::new(GenId(7), LUKS, ESP, HARDENING), Ok(ctx()));
}

#[test]
fn new_accepts_uuids_in_either_case() {
    let upper = LUKS.to_uppercase();
    let c = RenderCtx::new(GenId(1), &upper, "7a1b-2c3d", HARDENING).unwrap();
    assert_eq!(c.luks_uuid, upper);
    assert_eq!(c.esp_uuid, "7a1b-2c3d");
}

#[test]
fn new_accepts_a_canonical_uuid_for_the_esp() {
    let c = RenderCtx::new(GenId(1), LUKS, LUKS, HARDENING).unwrap();
    assert_eq!(c.esp_uuid, LUKS);
}

#[test]
fn new_rejects_a_malformed_luks_uuid() {
    for bad in [
        "",
        "0b6c2e7f5d0a4c2e9a713f1d2c4b5a69",
        "0b6c2e7f-5d0a-4c2e-9a71-3f1d2c4b5a6",
        "0b6c2e7f-5d0a-4c2e-9a71-3f1d2c4b5a690",
        "0b6c2e7f-5d0a4-c2e-9a71-3f1d2c4b5a69",
        "zb6c2e7f-5d0a-4c2e-9a71-3f1d2c4b5a69",
        "0b6c2e7f-5d0a-4c2e-9a71-3f1d2c4b5a69=evil",
        "0b6c2e7f-5d0a-4c2e-9a71-3f1d2c4b5a69 rw",
        "7A1B-2C3D",
    ] {
        let err = RenderCtx::new(GenId(1), bad, ESP, HARDENING).unwrap_err();
        assert!(err.contains("LUKS"), "{bad:?}: {err}");
    }
}

#[test]
fn new_rejects_a_malformed_esp_volume_id() {
    for bad in [
        "",
        "7A1B2C3D",
        "7A1B-2C3",
        "7A1B-2C3DE",
        "7A1B-2C3G",
        "7A1B_2C3D",
        "7A1B-2C3D noauto",
        "0b6c2e7f-5d0a-4c2e-9a71-3f1d2c4b5a6",
    ] {
        let err = RenderCtx::new(GenId(1), LUKS, bad, HARDENING).unwrap_err();
        assert!(err.contains("ESP"), "{bad:?}: {err}");
    }
}

#[test]
fn new_rejects_quotes_and_control_characters_in_the_hardening_cmdline() {
    for bad in [
        "quiet init=\"/bin/sh\"\n",
        "quiet\tslab_nomerge\n",
        "quiet\r\n",
        "quiet\0\n",
        "quiet\u{1b}[2J\n",
    ] {
        let err = RenderCtx::new(GenId(1), LUKS, ESP, bad).unwrap_err();
        assert!(err.contains("hardening"), "{bad:?}: {err}");
    }
}

#[test]
fn new_allows_newlines_in_the_hardening_cmdline() {
    let text = "quiet\nslab_nomerge\n\n";
    let c = RenderCtx::new(GenId(1), LUKS, ESP, text).unwrap();
    assert_eq!(c.hardening_cmdline, text);
}
