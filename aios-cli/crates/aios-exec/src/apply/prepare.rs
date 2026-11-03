use super::{mkdir, Mode, Run, CANDIDATES, ETC_CAND, ROOT_CAND, USR_CAND};
use crate::{btrfs, check_trusted_dirs, run_ok, Cmd, ExecError};
use aios_gen::{next_id, parse_subvol, GenId};

/// `-c` options for every git call: hooks point at `/dev/null` (there are none), and
/// neither an fsmonitor program nor a signing program runs.
const GIT_SAFETY: [&str; 6] = [
    "-c",
    "core.hooksPath=/dev/null",
    "-c",
    "core.fsmonitor=false",
    "-c",
    "commit.gpgsign=false",
];

impl Run<'_> {
    /// Mount the top level (apply only; bootstrap gets it mounted) and pick the generation
    /// id: max of every `@usr-gen-*`/`@etc-gen-*` + 1, or gen-1 on an empty bootstrap target.
    /// Then make the top level private (`mount --make-rprivate`), since the candidate tree
    /// is bound from it. A bootstrap target that already holds generations is refused
    /// before anything is run on it.
    pub(super) fn mount_top(&mut self) -> Result<(), ExecError> {
        let l = self.ctx.layout;
        if let Mode::Apply { .. } = self.ctx.mode {
            btrfs::mount_top(self.ctx.runner, &l.device, &l.top, false)?;
            self.top_mounted = true;
        }
        let ids: Vec<GenId> = btrfs::list_names(&l.top)?
            .iter()
            .filter_map(|name| parse_subvol(name))
            .map(|(_, id)| id)
            .collect();
        self.gen = match self.ctx.mode {
            Mode::Bootstrap if !ids.is_empty() => {
                return Err(ExecError(format!(
                    "{} already holds generations",
                    l.top.display()
                )))
            }
            Mode::Bootstrap => GenId(1),
            Mode::Apply { .. } => next_id(&ids)
                .ok_or_else(|| ExecError::new("no generation ids left (gen-9999 exists)"))?,
        };
        btrfs::make_rprivate(self.ctx.runner, &l.top)
    }

    /// The manifest repo and secrets are trusted (`check_trusted_dirs`) and the machine
    /// facts render safely (`RenderCtx::new`).
    pub(super) fn validate(&mut self) -> Result<(), ExecError> {
        check_trusted_dirs(self.ctx.layout, self.ctx.trusted_uid)?;
        self.ctx.facts.render_ctx(self.gen).map(drop)
    }

    /// Commit a dirty manifest repo (new files included) and record `HEAD`. git runs as
    /// root here, so the repo's own config gets no say in running programs: no hooks, no
    /// fsmonitor, no signing (spec §4.3 step 1).
    pub(super) fn commit_manifest(&mut self) -> Result<(), ExecError> {
        let runner = self.ctx.runner;
        let git = || {
            Cmd::new("git")
                .arg("-C")
                .arg_path(&self.ctx.layout.config)
                .args(GIT_SAFETY)
        };
        let status = run_ok(runner, &git().args(["status", "--porcelain"]))?;
        if !status.stdout_text().trim().is_empty() {
            run_ok(runner, &git().args(["add", "-A"]))?;
            let identity = ["-c", "user.name=aios", "-c", "user.email=aios@localhost"];
            let commit = git().args(identity).args(["commit", "--no-verify", "-m"]);
            run_ok(
                runner,
                &commit.arg(format!("aios: manifest for gen-{}", self.gen)),
            )?;
        }
        let head = run_ok(runner, &git().args(["rev-parse", "--short", "HEAD"]))?;
        self.manifest_commit = head.stdout_text().trim().to_string();
        if self.manifest_commit.is_empty() {
            return Err(ExecError::new("git rev-parse printed no commit"));
        }
        Ok(())
    }

    /// Unmount a candidate tree left mounted by a run that crashed earlier in this boot,
    /// delete stale candidates, then create fresh ones: snapshots of the booted generation
    /// (apply) or empty subvolumes (bootstrap), plus `@blank` -> `@root-cand`. From here on
    /// a failure deletes the candidates.
    pub(super) fn prepare_candidate(&mut self) -> Result<(), ExecError> {
        let (runner, l) = (self.ctx.runner, self.ctx.layout);
        self.candidates = true;
        // Counted as mounted until known otherwise, so a check that fails makes the
        // cleanup unmount before it deletes anything.
        self.cand_mounted = true;
        if btrfs::is_mountpoint(runner, &l.cand)? {
            btrfs::umount_recursive(runner, &l.cand)?;
        }
        self.cand_mounted = false;
        for name in CANDIDATES {
            btrfs::delete_recursive(runner, &l.subvol(name))?;
        }
        let blank = l.subvol("@blank");
        let mut sources = vec![blank.clone()];
        if let Mode::Apply { booted } = self.ctx.mode {
            sources.push(l.subvol(&booted.usr_subvol()));
            sources.push(l.subvol(&booted.etc_subvol()));
        }
        if let Some(missing) = sources.iter().find(|s| !s.is_dir()) {
            return Err(ExecError(format!("{} is missing", missing.display())));
        }
        match self.ctx.mode {
            Mode::Apply { booted } => {
                let usr = l.subvol(&booted.usr_subvol());
                btrfs::snapshot(runner, &usr, &l.subvol(USR_CAND))?;
                let etc = l.subvol(&booted.etc_subvol());
                btrfs::snapshot(runner, &etc, &l.subvol(ETC_CAND))?;
            }
            Mode::Bootstrap => {
                btrfs::create(runner, &l.subvol(USR_CAND))?;
                btrfs::create(runner, &l.subvol(ETC_CAND))?;
            }
        }
        btrfs::snapshot(runner, &blank, &l.subvol(ROOT_CAND))
    }

    /// Mount the candidate tree at `layout.cand`: `@root-cand`, with `@usr-cand` on `usr`,
    /// `@etc-cand` on `etc`, and binds of the pacman cache, `/var/log` and the local repo.
    pub(super) fn assemble(&mut self) -> Result<(), ExecError> {
        let (runner, l) = (self.ctx.runner, self.ctx.layout);
        mkdir(&l.cand)?;
        btrfs::bind(runner, &l.subvol(ROOT_CAND), &l.cand)?;
        self.cand_mounted = true;
        let binds = [
            (l.subvol(USR_CAND), "usr"),
            (l.subvol(ETC_CAND), "etc"),
            (l.pkg_cache(), "var/cache/pacman/pkg"),
            (l.log.clone(), "var/log"),
            (l.repo(), "persist/aios/repo"),
        ];
        for (source, rel) in binds {
            let target = l.cand.join(rel);
            mkdir(&source)?;
            mkdir(&target)?;
            btrfs::bind(runner, &source, &target)?;
        }
        Ok(())
    }
}
