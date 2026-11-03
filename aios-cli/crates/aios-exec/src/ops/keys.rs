use crate::{luks_uuid_from_cmdline, run_ok, Cmd, CommandRunner, ExecError, Layout};
use serde::Deserialize;
use std::fs;

/// The fields of `sbctl status --json` that aios reads.
#[derive(Deserialize)]
struct SbctlStatus {
    #[serde(default)]
    setup_mode: bool,
    #[serde(default)]
    secure_boot: bool,
}

fn sbctl_status(runner: &dyn CommandRunner) -> Result<SbctlStatus, ExecError> {
    let cmd = Cmd::new("sbctl").args(["status", "--json"]);
    let out = run_ok(runner, &cmd)?;
    serde_json::from_slice(&out.stdout).map_err(|e| ExecError(format!("`{cmd}`: {e}")))
}

/// Printed when the firmware is not in Setup Mode.
pub const SETUP_MODE_HELP: &str = "the firmware is not in Secure Boot Setup Mode, so keys \
cannot be enrolled. Reboot into the firmware setup, clear (reset) the Secure Boot keys to \
enter Setup Mode, boot AIOS again and re-run `aios secureboot enroll`";

/// `aios secureboot enroll`: in Setup Mode, enroll our keys plus Microsoft's (GPU option
/// ROMs need them). Otherwise an error explaining how to enter Setup Mode.
pub fn secureboot_enroll(runner: &dyn CommandRunner) -> Result<String, ExecError> {
    if !sbctl_status(runner)?.setup_mode {
        return Err(ExecError::new(SETUP_MODE_HELP));
    }
    run_ok(
        runner,
        &Cmd::new("sbctl").args(["enroll-keys", "--microsoft"]),
    )?;
    Ok(
        "Secure Boot keys enrolled. Enable Secure Boot in the firmware if it is off, \
reboot, then run `aios tpm enroll`."
            .to_string(),
    )
}

/// `aios tpm enroll`: with Secure Boot on, bind the LUKS volume to TPM2 PCR 7 plus a PIN.
/// The passphrase and recovery key slots stay.
pub fn tpm_enroll(runner: &dyn CommandRunner, layout: &Layout) -> Result<String, ExecError> {
    if !sbctl_status(runner)?.secure_boot {
        return Err(ExecError::new(
            "Secure Boot is not enabled: run `aios secureboot enroll`, enable Secure Boot \
in the firmware, reboot and retry",
        ));
    }
    let cmdline = fs::read_to_string(&layout.proc_cmdline)
        .map_err(|e| ExecError::io(&layout.proc_cmdline, e))?;
    let uuid = luks_uuid_from_cmdline(&cmdline)
        .ok_or_else(|| ExecError::new("no rd.luks.name=<uuid>=aios on the kernel cmdline"))?;
    let device = format!("/dev/disk/by-uuid/{uuid}");
    let cmd = Cmd::new("systemd-cryptenroll").args([
        "--tpm2-device=auto",
        "--tpm2-with-pin=yes",
        "--tpm2-pcrs=7",
        &device,
    ]);
    run_ok(runner, &cmd)?;
    Ok(format!(
        "TPM2 + PIN enrolled for {device}; the passphrase and recovery key still work"
    ))
}
