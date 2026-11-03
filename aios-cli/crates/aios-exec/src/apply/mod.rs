//! `aios apply` and `aios bootstrap`: build the next generation in candidate subvolumes
//! (spec §4.3). The booted generation is never modified; any failure (or panic) deletes
//! the candidates again.

mod etc;
mod finalize;
mod packages;
mod pkgdirs;
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
    /// For the user to see, not errors: package files outside `/usr` and `/etc`, which
    /// every boot loses (spec §4.3 step 5), and what failed after the new generation was
    /// installed (spec §7). The apply still succeeded.
    pub warnings: Vec<String>,
}

/// Build the next generation. On error or panic, the candidate tree is unmounted, every
/// candidate subvolume is deleted and the top level is unmounted (best effort, logged to
/// stderr; see `Run::cleanup`).
pub fn apply(ctx: &ApplyCtx) -> Result<ApplyOutcome, StepError> {
    let mut run = Run {
        ctx,
        gen: GenId(0),
        manifest_commit: String::new(),
        top_mounted: false,
        cand_mounted: false,
        candidates: false,
        ukis: Vec::new(),
        esp_tmp: Vec::new(),
        warnings: Vec::new(),
        done: false,
    };
    // A failed step returns here and drops `run`, which cleans up; so does a panic.
    run.steps()?;
    run.done = true;
    Ok(ApplyOutcome {
        gen: run.gen,
        manifest_commit: std::mem::take(&mut run.manifest_commit),
        ukis: run.ukis.iter().map(UkiName::file_name).collect(),
        warnings: std::mem::take(&mut run.warnings),
    })
}

/// State of one apply, shared by the step implementations in the submodules. Dropping it
/// before it is `done` runs the cleanup.
struct Run<'a> {
    ctx: &'a ApplyCtx<'a>,
    /// The generation being built. Set by `mount-top`.
    gen: GenId,
    manifest_commit: String,
    /// We mounted `layout.top` and must unmount it.
    top_mounted: bool,
    /// Something is mounted at `layout.cand`.
    cand_mounted: bool,
    /// The candidate subvolumes are this run's to delete. Set by `prepare-candidate`, so a
    /// target that bootstrap refuses (it holds a system, maybe mid-apply) is never touched.
    candidates: bool,
    /// UKIs built in the candidate.
    ukis: Vec<UkiName>,
    /// UKI copies on the ESP not yet renamed into place.
    esp_tmp: Vec<PathBuf>,
    /// See `ApplyOutcome::warnings`.
    warnings: Vec<String>,
    /// Every step succeeded: nothing to clean up.
    done: bool,
}

impl Drop for Run<'_> {
    fn drop(&mut self) {
        if !self.done {
            self.cleanup();
        }
    }
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

    /// Undo everything that is not finalized. Errors are logged, not returned. While the
    /// candidate tree is still mounted (its unmount failed), its subvolumes are kept:
    /// `aios-root.service` deletes them at the next boot.
    fn cleanup(&mut self) {
        eprintln!("aios: {}", Step::Cleanup);
        let (runner, l) = (self.ctx.runner, self.ctx.layout);
        let report = |what: &str, result: Result<(), ExecError>| {
            if let Err(e) = result {
                eprintln!("aios: cleanup: {what}: {e}");
            }
        };
        if self.cand_mounted {
            match btrfs::umount_recursive(runner, &l.cand) {
                Ok(()) => self.cand_mounted = false,
                Err(e) => report("unmount candidate", Err(e)),
            }
        }
        if self.candidates && self.cand_mounted {
            eprintln!(
                "aios: cleanup: {} is still mounted, so the candidate subvolumes stay; the \
                 next boot deletes them",
                l.cand.display()
            );
        } else if self.candidates {
            for name in CANDIDATES {
                report(name, btrfs::delete_recursive(runner, &l.subvol(name)));
            }
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
