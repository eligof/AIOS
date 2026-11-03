mod common;

use aios_exec::ops::{secureboot_enroll, tpm_enroll};
use aios_exec::Output;
use common::{write, Fixture, LUKS_UUID};

fn sbctl_says(fx: &mut Fixture, json: &str) {
    fx.runner
        .respond(&["sbctl", "status", "--json"], Output::ok(json));
}

const SETUP: &str =
    r#"{"installed":true,"guid":"x","setup_mode":true,"secure_boot":false,"vendors":[]}"#;
const ENFORCING: &str = r#"{"installed":true,"guid":"x","setup_mode":false,"secure_boot":true,"vendors":["microsoft"]}"#;
const USER_MODE_OFF: &str = r#"{"installed":true,"setup_mode":false,"secure_boot":false}"#;

#[test]
fn enrolls_keys_in_setup_mode() {
    let mut fx = Fixture::booted();
    sbctl_says(&mut fx, SETUP);
    let message = secureboot_enroll(&fx.runner).unwrap();
    assert!(
        message.starts_with("Secure Boot keys enrolled."),
        "{message}"
    );
    assert_eq!(
        fx.calls(),
        ["sbctl status --json", "sbctl enroll-keys --microsoft"]
    );
}

#[test]
fn secure_boot_already_on_is_success() {
    let mut fx = Fixture::booted();
    sbctl_says(&mut fx, ENFORCING);
    assert_eq!(
        secureboot_enroll(&fx.runner).unwrap(),
        "Secure Boot is already enabled"
    );
    assert_eq!(fx.calls(), ["sbctl status --json"]);
}

#[test]
fn outside_setup_mode_explains_how_to_get_there() {
    let mut fx = Fixture::booted();
    sbctl_says(&mut fx, USER_MODE_OFF);
    let err = secureboot_enroll(&fx.runner).unwrap_err();
    assert!(
        err.to_string().contains("not in Secure Boot Setup Mode"),
        "{err}"
    );
    assert_eq!(fx.calls(), ["sbctl status --json"]);
}

#[test]
fn unparsable_sbctl_output_is_an_error() {
    let mut fx = Fixture::booted();
    sbctl_says(&mut fx, "Installed: yes");
    let err = secureboot_enroll(&fx.runner).unwrap_err();
    assert!(
        err.to_string().starts_with("`sbctl status --json`: "),
        "{err}"
    );
}

#[test]
fn tpm_enroll_binds_pcr7_with_a_pin() {
    let mut fx = Fixture::booted();
    sbctl_says(&mut fx, ENFORCING);
    let message = tpm_enroll(&fx.runner, &fx.layout).unwrap();
    assert!(message.contains(LUKS_UUID), "{message}");
    assert_eq!(
        fx.calls()[1],
        format!(
            "systemd-cryptenroll --tpm2-device=auto --tpm2-with-pin=yes --tpm2-pcrs=7 \
             --wipe-slot=tpm2 /dev/disk/by-uuid/{LUKS_UUID}"
        )
    );
    assert!(
        fx.runner.commands()[1].interactive,
        "systemd-cryptenroll prompts for the passphrase and the PIN"
    );
}

#[test]
fn tpm_enroll_refuses_setup_mode() {
    let mut fx = Fixture::booted();
    sbctl_says(
        &mut fx,
        r#"{"installed":true,"setup_mode":true,"secure_boot":true}"#,
    );
    let err = tpm_enroll(&fx.runner, &fx.layout).unwrap_err();
    assert!(
        err.to_string()
            .starts_with("the firmware is still in Secure Boot Setup Mode"),
        "{err}"
    );
    assert_eq!(fx.calls().len(), 1);
}

#[test]
fn tpm_enroll_needs_a_canonical_luks_uuid() {
    let mut fx = Fixture::booted();
    sbctl_says(&mut fx, ENFORCING);
    write(
        &fx.layout.proc_cmdline,
        "rd.luks.name=../../../dev/sda2=aios aios.gen=0007\n",
        0o644,
    );
    let err = tpm_enroll(&fx.runner, &fx.layout).unwrap_err();
    assert_eq!(
        err.to_string(),
        "no rd.luks.name=<uuid>=aios on the kernel cmdline"
    );
    assert_eq!(fx.calls().len(), 1, "systemd-cryptenroll never runs");
}

#[test]
fn tpm_enroll_needs_secure_boot() {
    let mut fx = Fixture::booted();
    sbctl_says(&mut fx, USER_MODE_OFF);
    let err = tpm_enroll(&fx.runner, &fx.layout).unwrap_err();
    assert!(
        err.to_string().starts_with("Secure Boot is not enabled"),
        "{err}"
    );
    assert_eq!(fx.calls().len(), 1);
}

#[test]
fn tpm_enroll_needs_the_luks_uuid_on_the_cmdline() {
    let mut fx = Fixture::booted();
    sbctl_says(&mut fx, ENFORCING);
    write(
        &fx.layout.proc_cmdline,
        "root=/dev/sda2 aios.gen=0007\n",
        0o644,
    );
    let err = tpm_enroll(&fx.runner, &fx.layout).unwrap_err();
    assert_eq!(
        err.to_string(),
        "no rd.luks.name=<uuid>=aios on the kernel cmdline"
    );
}
