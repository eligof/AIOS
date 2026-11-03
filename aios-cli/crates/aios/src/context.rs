use crate::failure::Failure;
use crate::lock::{self, Lock};
use aios_exec::{
    check_trusted_dirs, luks_uuid_from_cmdline, run_ok, Cmd, CommandRunner, FakeRunner, Layout,
    MachineFacts, RealRunner, Step, StepError,
};
use aios_gen::{gen_from_cmdline, GenId};
use aios_manifest::{load, Manifest, ValidationEnv};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

/// Paths, the command runner and environment overrides for one `aios` invocation.
pub struct Context {
    pub layout: Layout,
    runner: Box<dyn CommandRunner>,
    /// `AIOS_FAKE_RUNNER` is set (tests): no root check, commands are scripted, the
    /// manifest repo must belong to the caller instead of root, and `aios passwd` reads
    /// `AIOS_TEST_PASSWORD`.
    pub fake: bool,
    zoneinfo: PathBuf,
    hardening_file: PathBuf,
}

fn env_path(name: &str, default: &str) -> PathBuf {
    env::var_os(name).map_or_else(|| default.into(), PathBuf::from)
}

impl Context {
    pub fn from_env() -> Result<Context, Failure> {
        let script = env::var_os("AIOS_FAKE_RUNNER");
        let runner: Box<dyn CommandRunner> = match &script {
            Some(path) => Box::new(FakeRunner::from_json_file(Path::new(path))?),
            None => Box::new(RealRunner),
        };
        Ok(Context {
            layout: Layout::from_env(),
            runner,
            fake: script.is_some(),
            zoneinfo: env_path("AIOS_ZONEINFO", "/usr/share/zoneinfo"),
            hardening_file: env_path(
                "AIOS_HARDENING_CMDLINE_FILE",
                "/usr/lib/aios/cmdline-hardening",
            ),
        })
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
        load(&self.layout.manifest_path(), &env).map_err(Failure::manifest)
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
