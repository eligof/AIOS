use super::{lines, mkdir, Mode, Run};
use crate::{days_since_epoch, etcfs, read_etc_entry, read_hashes, rfc3339_utc, run_ok};
use crate::{sha256_hex, Cmd, DirProbe, ExecError};
use aios_gen::GenerationMeta;
use aios_plan::{desired_etc, EtcEntry, Inputs, GENERATION_TOML, MANAGED_FILES};
use aios_render::{home_binds, parse_managed_list, persist_dirs};
use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

impl Run<'_> {
    /// Spec §4.3 steps 5–6: write the desired `/etc` (files, generated config, merged
    /// accounts, home bind sources) into `@etc-cand`, drop paths the previous generation
    /// managed and this one doesn't, write `generation.toml`, run `locale-gen`, apply
    /// `[files]` owners, and create the persist directories the binds need (plus, for
    /// bootstrap, the home directories).
    pub(super) fn render_etc(&mut self) -> Result<(), ExecError> {
        let (runner, l, m) = (self.ctx.runner, self.ctx.layout, self.ctx.manifest);
        let etc = l.cand.join("etc");
        let render = self.ctx.facts.render_ctx(self.gen)?;
        let hashes = read_hashes(l, m)?;
        let inputs = Inputs {
            manifest: m,
            repo_root: &l.config,
            ctx: &render,
            hashes: &hashes,
            today_days: days_since_epoch(self.ctx.now),
        };
        let probe = DirProbe::new(&etc, runner, Some(l.cand.clone()));
        let desired = desired_etc(&inputs, &probe).map_err(|e| ExecError(e.to_string()))?;

        let previous = read_etc_entry(&etc, MANAGED_FILES).map_err(|e| ExecError(e.0))?;
        if let Some(EtcEntry::File { content, .. }) = previous {
            let old = parse_managed_list(&String::from_utf8_lossy(&content))
                .map_err(|e| ExecError(format!("{MANAGED_FILES}: {e}")))?;
            for path in old {
                if !desired.contains_key(&path) {
                    etcfs::remove(&etc, &path)?;
                }
            }
        }
        for (path, entry) in &desired {
            etcfs::write(&etc, path, entry)?;
        }
        for bind in home_binds(m).iter().filter(|b| b.is_dir) {
            etcfs::create_dirs(&etc, &bind.bind_source)?;
        }
        self.write_generation_toml(&etc)?;

        if desired.contains_key("/etc/locale.gen") {
            self.chroot(&["locale-gen"], &[])?;
        }
        for (path, file) in &m.files {
            let (owner, group) = (file.owner_or_default(), file.group_or_default());
            if owner != "root" || group != "root" {
                let spec = format!("{owner}:{group}");
                self.chroot(&["chown", "-h", &spec, path], &[])?;
            }
        }
        for dir in persist_dirs(m) {
            mkdir(&l.persist_path(&dir))?;
        }
        if self.ctx.mode == Mode::Bootstrap {
            self.home_dirs()?;
        }
        Ok(())
    }

    fn write_generation_toml(&self, etc: &Path) -> Result<(), ExecError> {
        let m = self.ctx.manifest;
        let kernels: Vec<String> = std::iter::once(m.kernel.default.clone())
            .chain(m.kernel.fallback.clone())
            .collect();
        let versions = self.chroot(&["pacman", "-Q"], &kernels)?;
        let mut packages = lines(&self.chroot(&["pacman", "-Qq"], &[])?.stdout_text());
        packages.sort();
        let listing: String = packages.iter().map(|p| format!("{p}\n")).collect();
        let meta = GenerationMeta {
            id: self.gen.get(),
            parent: match self.ctx.mode {
                Mode::Apply { booted } => booted.get(),
                Mode::Bootstrap => 0,
            },
            created: rfc3339_utc(self.ctx.now),
            manifest_commit: self.manifest_commit.clone(),
            kernels: lines(&versions.stdout_text()),
            package_set_sha256: sha256_hex(listing.as_bytes()),
        };
        let entry = EtcEntry::File {
            content: meta.to_toml().into_bytes(),
            mode: 0o644,
        };
        etcfs::write(etc, GENERATION_TOML, &entry)
    }

    /// Bootstrap only: `/home/<user>` (0700, chowned to `uid:uid`) on the new `@home`.
    /// Apply never touches `/home`: the `aios-home.conf` `d` lines fix ownership at boot
    /// and systemd creates the bind mount points itself.
    fn home_dirs(&self) -> Result<(), ExecError> {
        for (name, user) in &self.ctx.manifest.users {
            let home = self.ctx.layout.home.join(name);
            match fs::symlink_metadata(&home) {
                Ok(meta) if meta.file_type().is_symlink() || !meta.is_dir() => {
                    return Err(ExecError(format!(
                        "{}: exists and is not a directory",
                        home.display()
                    )))
                }
                Ok(_) => continue,
                Err(e) if e.kind() == ErrorKind::NotFound => {}
                Err(e) => return Err(ExecError::io(&home, e)),
            }
            let io = |e: std::io::Error| ExecError::io(&home, e);
            fs::create_dir(&home).map_err(io)?;
            fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).map_err(io)?;
            let owner = format!("{0}:{0}", user.uid);
            run_ok(
                self.ctx.runner,
                &Cmd::new("chown").arg(owner).arg_path(&home),
            )?;
        }
        Ok(())
    }
}
