use crate::failure::Failure;
use crate::lock::{self, Lock};
use aios_exec::{
    check_trusted_dirs, luks_uuid_from_cmdline, run_ok, Cmd, CommandRunner, Layout, MachineFacts,
    RealRunner, Step, StepError,
};
use aios_gen::{gen_from_cmdline, GenId};
use aios_manifest::{load, Manifest, ValidationEnv};
use rustix::mount::{mount_change, MountPropagationFlags};
use rustix::thread::UnshareFlags;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

/// The test override named `name` (an `AIOS_*` environment variable). Only builds with the
/// `test-hooks` feature, which the CLI tests require, read it: a release build has no
/// overrides at all. Every `AIOS_*` lookup goes through here.
#[cfg(feature = "test-hooks")]
fn hook(name: &str) -> Option<OsString> {
    std::env::var_os(name)
}

/// Release builds: no overrides.
#[cfg(not(feature = "test-hooks"))]
#[inline(always)]
fn hook(_name: &str) -> Option<OsString> {
    None
}

fn hook_path(name: &str, default: &str) -> PathBuf {
    hook(name).map_or_else(|| default.into(), PathBuf::from)
}

/// The scripted runner `AIOS_FAKE_RUNNER` names, if any.
fn fake_runner() -> Result<Option<Box<dyn CommandRunner>>, Failure> {
    #[cfg(feature = "test-hooks")]
    if let Some(script) = hook("AIOS_FAKE_RUNNER") {
        let fake = aios_exec::FakeRunner::from_json_file(script.as_ref())?;
        return Ok(Some(Box::new(fake)));
    }
    Ok(None)
}

/// Paths, the command runner and test overrides for one `aios` invocation.
pub struct Context {
    pub layout: Layout,
    runner: Box<dyn CommandRunner>,
    /// `AIOS_FAKE_RUNNER` is set (test builds only): no root check, commands are scripted,
    /// the manifest repo must belong to the caller instead of root, and `aios passwd`
    /// reads `AIOS_TEST_PASSWORD`.
    pub fake: bool,
    zoneinfo: PathBuf,
    hardening_file: PathBuf,
}

impl Context {
    /// The production context; in a `test-hooks` build, with any `AIOS_*` override.
    pub fn new() -> Result<Context, Failure> {
        let fake = fake_runner()?;
        Ok(Context {
            layout: Layout::from_vars(hook),
            fake: fake.is_some(),
            runner: fake.unwrap_or_else(|| Box::new(RealRunner)),
            zoneinfo: hook_path("AIOS_ZONEINFO", "/usr/share/zoneinfo"),
            hardening_file: hook_path(
                "AIOS_HARDENING_CMDLINE_FILE",
                "/usr/lib/aios/cmdline-hardening",
            ),
        })
    }

    /// Under `AIOS_FAKE_RUNNER`, `aios passwd` takes `AIOS_TEST_PASSWORD` instead of
    /// prompting. `None`: prompt.
    #[cfg(feature = "test-hooks")]
    pub fn test_password(&self) -> Option<Result<String, Failure>> {
        self.fake.then(|| {
            hook("AIOS_TEST_PASSWORD")
                .and_then(|password| password.into_string().ok())
                .ok_or_else(|| Failure::op("aios: AIOS_TEST_PASSWORD is not set"))
        })
    }

    /// Release builds always prompt.
    #[cfg(not(feature = "test-hooks"))]
    pub fn test_password(&self) -> Option<Result<String, Failure>> {
        None
    }

    pub fn runner(&self) -> &dyn CommandRunner {
        self.runner.as_ref()
    }

    /// Every command mounts, writes secrets or changes boot state, so all need root.
    pub fn require_root(&self) -> Result<(), Failure> {
        if self.fake || rustix::process::geteuid().is_root() {
            Ok(())
        } else {
            Err(Failure::op("aios: must run as root (try: run0 aios <cmd>)"))
        }
    }

    /// Run the rest of this process in a private mount namespace in which `/` is,
    /// recursively, a slave of the host's mounts. The mounts aios and its children make
    /// (the top level, the candidate tree and its binds) are then never seen outside this
    /// process and go away with it, even when it is killed, while mounts made outside (the
    /// `/efi` automount) still propagate in. For every command that mounts the top level:
    /// apply, bootstrap, gc, rollback, and the readers plan, status and gen list, whose
    /// `ro.<pid>` mount a SIGKILL could otherwise leak. Call it before any thread starts:
    /// `unshare` moves only the calling thread, and children inherit its namespace. A no-op
    /// under `AIOS_FAKE_RUNNER`, which mounts nothing; it needs root, so only the e2e test
    /// covers it (spec §9).
    pub fn private_mounts(&self) -> Result<(), Failure> {
        if self.fake {
            return Ok(());
        }
        let failed = |what: &str, e: rustix::io::Errno| {
            Failure::op(format!(
                "aios: cannot make a private mount namespace ({what}): {e}"
            ))
        };
        rustix::thread::unshare(UnshareFlags::NEWNS).map_err(|e| failed("unshare", e))?;
        mount_change(
            "/",
            MountPropagationFlags::SLAVE | MountPropagationFlags::REC,
        )
        .map_err(|e| failed("making / a recursive slave", e))
    }

    pub fn lock(&self, exclusive: bool) -> Result<Lock, Failure> {
        lock::acquire(&self.layout.lock, exclusive)
    }

    /// Owner the manifest repo and secrets must have: root, or the caller under
    /// `AIOS_FAKE_RUNNER`.
    pub fn trusted_uid(&self) -> u32 {
        if self.fake {
            rustix::process::geteuid().as_raw()
        } else {
            0
        }
    }

    /// Check the manifest repo and secrets ownership, then load and validate
    /// `<config>/manifest.toml`. Problems with the manifest exit 2.
    pub fn load_manifest(&self) -> Result<Manifest, Failure> {
        self.load_manifest_at(&self.layout.manifest_path())
    }

    /// Like `load_manifest`, for the manifest file `path` in the repo `layout.config`.
    pub fn load_manifest_at(&self, path: &Path) -> Result<Manifest, Failure> {
        check_trusted_dirs(&self.layout, self.trusted_uid()).map_err(|e| {
            Failure::from(StepError {
                step: Step::Validate,
                detail: e.0,
            })
        })?;
        let env = ValidationEnv {
            repo_root: self.layout.config.clone(),
            secrets_dir: self.layout.secrets.clone(),
            zoneinfo_dir: self.zoneinfo.clone(),
        };
        load(path, &env).map_err(Failure::manifest)
    }

    /// The generation the running kernel booted (`aios.gen=`).
    pub fn booted(&self) -> Result<GenId, Failure> {
        let path = &self.layout.proc_cmdline;
        let cmdline = fs::read_to_string(path)
            .map_err(|e| Failure::op(format!("aios: {}: {e}", path.display())))?;
        gen_from_cmdline(&cmdline).ok_or_else(|| {
            Failure::op("aios: no single aios.gen= on the kernel cmdline; is this an AIOS boot?")
        })
    }

    /// Hardening cmdline, LUKS UUID (`luks_uuid`, else the running cmdline's
    /// `rd.luks.name=`) and the ESP's volume id (`findmnt`).
    pub fn facts(&self, luks_uuid: Option<String>) -> Result<MachineFacts, Failure> {
        let path = &self.hardening_file;
        let hardening_cmdline = fs::read_to_string(path)
            .map_err(|e| Failure::op(format!("aios: {}: {e}", path.display())))?;
        let luks_uuid = match luks_uuid {
            Some(uuid) => uuid,
            None => fs::read_to_string(&self.layout.proc_cmdline)
                .ok()
                .and_then(|cmdline| luks_uuid_from_cmdline(&cmdline))
                .ok_or_else(|| {
                    Failure::op("aios: no rd.luks.name=<uuid>=aios on the kernel cmdline")
                })?,
        };
        Ok(MachineFacts {
            hardening_cmdline,
            luks_uuid,
            esp_uuid: self.esp_uuid()?,
        })
    }

    fn esp_uuid(&self) -> Result<String, Failure> {
        let esp = &self.layout.esp;
        // Touch the mount point first: /efi is an automount, and findmnt alone would only
        // see the autofs entry.
        let _ = fs::read_dir(esp);
        let out = run_ok(
            self.runner(),
            &Cmd::new("findmnt").args(["-no", "UUID"]).arg_path(esp),
        )?;
        out.stdout_text()
            .lines()
            .map(str::trim)
            .rev()
            .find(|line| !line.is_empty())
            .map(str::to_string)
            .ok_or_else(|| {
                Failure::op(format!("aios: findmnt shows no UUID for {}", esp.display()))
            })
    }
}

#[cfg(test)]
mod tests {
    use super::hook;

    /// PATH is always set, but only a `test-hooks` build may see it through `hook`.
    #[test]
    fn hooks_read_the_environment_only_in_test_hook_builds() {
        assert_eq!(hook("PATH").is_some(), cfg!(feature = "test-hooks"));
    }
}
