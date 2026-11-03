use super::{mkdir, Mode, Run};
use crate::{ops, parse_df_avail, run_ok, Cmd, ExecError};
use aios_gen::{Flavor, UkiName};
use std::collections::BTreeMap;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

/// Where UKIs are built, as seen inside the candidate.
const BUILD_DIR: &str = "/var/tmp/aios";

impl Run<'_> {
    /// Spec §4.3 step 8, for the default kernel (`cachyos`) and the fallback (`lts`): an
    /// initramfs (microcode comes from mkinitcpio's `microcode` hook) and a UKI.
    pub(super) fn uki(&mut self) -> Result<(), ExecError> {
        let (l, m) = (self.ctx.layout, self.ctx.manifest);
        let versions = module_versions(&l.cand.join("usr/lib/modules"))?;
        mkdir(&self.build_dir())?;
        let kernels = std::iter::once((&m.kernel.default, Flavor::Main))
            .chain(m.kernel.fallback.iter().map(|k| (k, Flavor::Fallback)));
        for (kernel, flavor) in kernels {
            let version = match versions.get(kernel.as_str()).map(Vec::as_slice) {
                Some([only]) => only.clone(),
                Some(several) if several.len() > 1 => {
                    return Err(ExecError(format!(
                        "several module directories for {kernel}: {}",
                        several.join(", ")
                    )))
                }
                _ => {
                    return Err(ExecError(format!(
                        "no /usr/lib/modules/*/pkgbase names {kernel}"
                    )))
                }
            };
            let initrd = format!("{BUILD_DIR}/initramfs-{}.img", flavor.token());
            let name = UkiName::fresh(self.gen, flavor);
            self.chroot(&["mkinitcpio", "-k", &version, "-g", &initrd], &[])?;
            self.chroot(
                &[
                    "ukify",
                    "build",
                    &format!("--linux=/usr/lib/modules/{version}/vmlinuz"),
                    &format!("--initrd={initrd}"),
                    "--cmdline=@/etc/kernel/cmdline",
                    "--os-release=@/usr/lib/os-release",
                    &format!("--output={BUILD_DIR}/{}", name.entry_id()),
                ],
                &[],
            )?;
            self.ukis.push(name);
        }
        Ok(())
    }

    fn build_dir(&self) -> PathBuf {
        self.ctx.layout.cand.join(BUILD_DIR.trim_start_matches('/'))
    }

    /// Host path of a UKI built in the candidate.
    pub(super) fn built_uki(&self, name: &UkiName) -> PathBuf {
        self.build_dir().join(name.entry_id())
    }

    /// Sign each UKI on the host with the sbctl keys (spec §4.3 step 9).
    pub(super) fn sign(&mut self) -> Result<(), ExecError> {
        for name in &self.ukis {
            let cmd = Cmd::new("sbctl").arg("sign").arg_path(self.built_uki(name));
            run_ok(self.ctx.runner, &cmd)?;
        }
        Ok(())
    }

    /// The ESP needs 1.2 × the new UKIs' size free. If it doesn't have it, delete old
    /// generations (`gc`, keep 5) and check again (spec §4.3 step 10).
    pub(super) fn esp_space(&mut self) -> Result<(), ExecError> {
        let l = self.ctx.layout;
        remove_stale_copies(&l.uki_dir())?;
        let mut total = 0;
        for name in &self.ukis {
            let path = self.built_uki(name);
            total += fs::metadata(&path)
                .map_err(|e| ExecError::io(&path, e))?
                .len();
        }
        let need = (total * 6).div_ceil(5);
        let mut free = self.esp_free()?;
        if free < need {
            eprintln!("aios: the ESP has {free} bytes free and needs {need}: running gc");
            let mode = match self.ctx.mode {
                Mode::Apply { .. } => ops::GcMode::Running,
                Mode::Bootstrap => ops::GcMode::Bootstrap,
            };
            ops::gc_mounted(self.ctx.runner, l, 5, mode)?;
            free = self.esp_free()?;
        }
        if free < need {
            return Err(ExecError(format!(
                "{} has {free} bytes free, the new UKIs need {need}",
                l.esp.display()
            )));
        }
        Ok(())
    }

    fn esp_free(&self) -> Result<u64, ExecError> {
        let cmd = Cmd::new("df")
            .args(["--output=avail", "-B1"])
            .arg_path(&self.ctx.layout.esp);
        let out = run_ok(self.ctx.runner, &cmd)?;
        parse_df_avail(&out.stdout_text())
            .ok_or_else(|| ExecError(format!("`{cmd}` printed no free space")))
    }
}

/// `pkgbase` -> module directory names, from `/usr/lib/modules/*/pkgbase`.
fn module_versions(dir: &Path) -> Result<BTreeMap<String, Vec<String>>, ExecError> {
    let mut versions: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let entries = fs::read_dir(dir).map_err(|e| ExecError::io(dir, e))?;
    let mut names: Vec<String> = entries
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    for name in names {
        let pkgbase = dir.join(&name).join("pkgbase");
        match fs::read_to_string(&pkgbase) {
            Ok(text) => versions
                .entry(text.trim().to_string())
                .or_default()
                .push(name),
            Err(e) if matches!(e.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory) => {}
            Err(e) => return Err(ExecError::io(&pkgbase, e)),
        }
    }
    Ok(versions)
}

/// Delete `aios-gen-*.efi.tmp` copies an interrupted finalize left on the ESP.
fn remove_stale_copies(dir: &Path) -> Result<(), ExecError> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(ExecError::io(dir, e)),
    };
    for entry in entries.filter_map(Result::ok) {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with("aios-gen-") && name.ends_with(".efi.tmp") {
            let path = entry.path();
            fs::remove_file(&path).map_err(|e| ExecError::io(&path, e))?;
        }
    }
    Ok(())
}
