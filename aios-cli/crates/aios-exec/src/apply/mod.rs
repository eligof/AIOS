//! `aios apply` and `aios bootstrap`: build the next generation in candidate subvolumes
//! (spec §4.3). The booted generation is never modified; any failure deletes the
//! candidates again.

mod etc;
mod finalize;
mod packages;
mod prepare;
mod services;
mod uki;

use crate::{btrfs, run_ok, Cmd, CommandRunner, ExecError, Layout, MachineFacts, Output};
use crate::{Step, StepError};
use aios_gen::{GenId, UkiName};
use aios_manifest::Manifest;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

const USR_CAND: &str = "@usr-cand";
const ETC_CAND: &str = "@etc-cand";
const ROOT_CAND: &str = "@root-cand";
const CANDIDATES: [&str; 3] = [USR_CAND, ETC_CAND, ROOT_CAND];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// `aios apply`: snapshot the booted generation, `pacman -Syu`, then clear the
    /// `bootctl set-default` override so the new generation boots next.
    Apply { booted: GenId },
    /// `aios bootstrap` (installer): the top level is already mounted at `layout.top`;
    /// empty candidates, `pacstrap`, a fresh keyring, gen-1. No `bootctl` call.
    Bootstrap,
}

/// Everything one apply needs.
pub struct ApplyCtx<'a> {
    pub runner: &'a dyn CommandRunner,
    pub layout: &'a Layout,
    pub manifest: &'a Manifest,
    pub facts: &'a MachineFacts,
    /// Clock for `generation.toml` (`created`) and shadow `lastchg`.
    pub now: SystemTime,
    /// Required owner of the manifest repo and secrets directory: 0 in production.
    pub trusted_uid: u32,
    pub mode: Mode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyOutcome {
    pub gen: GenId,
    pub manifest_commit: String,
    /// The UKI file names now on the ESP.
    pub ukis: Vec<String>,
}

/// Build the next generation. On error, the candidate tree is unmounted, every candidate
/// subvolume is deleted and the top level is unmounted (best effort, logged to stderr).
pub fn apply(ctx: &ApplyCtx) -> Result<ApplyOutcome, StepError> {
    let mut run = Run {
        ctx,
        gen: GenId(0),
        manifest_commit: String::new(),
        top_mounted: false,
        cand_mounted: false,
        ukis: Vec::new(),
        esp_tmp: Vec::new(),
    };
    match run.steps() {
        Ok(()) => Ok(ApplyOutcome {
            gen: run.gen,
            manifest_commit: run.manifest_commit,
            ukis: run.ukis.iter().map(UkiName::file_name).collect(),
        }),
        Err(e) => {
            run.cleanup();
            Err(e)
        }
    }
}

/// State of one apply, shared by the step implementations in the submodules.
struct Run<'a> {
    ctx: &'a ApplyCtx<'a>,
    /// The generation being built. Set by `mount-top`.
    gen: GenId,
    manifest_commit: String,
    /// We mounted `layout.top` and must unmount it.
    top_mounted: bool,
    /// Something is mounted at `layout.cand`.
    cand_mounted: bool,
    /// UKIs built in the candidate.
    ukis: Vec<UkiName>,
    /// UKI copies on the ESP not yet renamed into place.
    esp_tmp: Vec<PathBuf>,
}

impl Run<'_> {
    fn steps(&mut self) -> Result<(), StepError> {
        self.step(Step::MountTop, Run::mount_top)?;
        self.step(Step::Validate, Run::validate)?;
        self.step(Step::CommitManifest, Run::commit_manifest)?;
        self.step(Step::PrepareCandidate, Run::prepare_candidate)?;
        self.step(Step::Assemble, Run::assemble)?;
        self.step(Step::Packages, Run::packages)?;
        if self.ctx.mode == Mode::Bootstrap {
            self.step(Step::Keyring, Run::keyring)?;
        }
        self.step(Step::RenderEtc, Run::render_etc)?;
        self.step(Step::Services, Run::services)?;
        self.step(Step::Uki, Run::uki)?;
        self.step(Step::Sign, Run::sign)?;
        self.step(Step::EspSpace, Run::esp_space)?;
        self.step(Step::Finalize, Run::finalize)
    }

    fn step(
        &mut self,
        step: Step,
        f: impl FnOnce(&mut Self) -> Result<(), ExecError>,
    ) -> Result<(), StepError> {
        eprintln!("aios: {step}");
        f(self).map_err(|e| StepError { step, detail: e.0 })
    }

    /// `arch-chroot <cand> ARGS...`
    fn chroot_cmd(&self, args: &[&str]) -> Cmd {
        Cmd::new("arch-chroot")
            .arg_path(&self.ctx.layout.cand)
            .args(args.iter().copied())
    }

    /// Run `arch-chroot <cand> ARGS... MORE...`; a non-zero exit is an error.
    fn chroot(&self, args: &[&str], more: &[String]) -> Result<Output, ExecError> {
        let cmd = self.chroot_cmd(args).args(more.iter().cloned());
        run_ok(self.ctx.runner, &cmd)
    }

    /// Undo everything that is not finalized. Errors are logged, not returned.
    fn cleanup(&mut self) {
        eprintln!("aios: {}", Step::Cleanup);
        let (runner, l) = (self.ctx.runner, self.ctx.layout);
        let report = |what: &str, result: Result<(), ExecError>| {
            if let Err(e) = result {
                eprintln!("aios: cleanup: {what}: {e}");
            }
        };
        if self.cand_mounted {
            report(
                "unmount candidate",
                btrfs::umount_recursive(runner, &l.cand),
            );
        }
        for name in CANDIDATES {
            report(name, btrfs::delete_recursive(runner, &l.subvol(name)));
        }
        for tmp in &self.esp_tmp {
            match fs::remove_file(tmp) {
                Err(e) if e.kind() != ErrorKind::NotFound => {
                    report("ESP", Err(ExecError::io(tmp, e)));
                }
                _ => {}
            }
        }
        if self.top_mounted {
            report("unmount top level", btrfs::umount(runner, &l.top));
        }
    }
}

/// `mkdir -p`.
fn mkdir(path: &Path) -> Result<(), ExecError> {
    fs::create_dir_all(path).map_err(|e| ExecError::io(path, e))
}

/// Non-empty, trimmed lines.
fn lines(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect()
}
