use super::{with_top, BootState};
use crate::{btrfs, CommandRunner, ExecError, Layout};
use aios_gen::{list_complete, GenId, GenerationMeta};
use std::fs;

/// One line of `aios gen list`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenRow {
    pub gen: GenId,
    /// From `generation.toml`; `?` when it can't be read.
    pub created: String,
    pub commit: String,
    pub kernels: Vec<String>,
    /// Any of `booted`, `default`, `bad`.
    pub states: Vec<&'static str>,
}

/// `aios gen list`: mount the top level read-only, read every generation, unmount.
pub fn gen_list(runner: &dyn CommandRunner, layout: &Layout) -> Result<Vec<GenRow>, ExecError> {
    with_top(runner, layout, true, gen_rows)
}

/// Every complete generation in the (mounted) top level, ascending.
pub fn gen_rows(layout: &Layout) -> Result<Vec<GenRow>, ExecError> {
    let state = BootState::read(layout)?;
    let bad = state.bad();
    let gens = list_complete(&btrfs::list_names(&layout.top)?);
    Ok(gens
        .into_iter()
        .map(|gen| {
            let path = layout
                .subvol(&gen.etc_subvol())
                .join("aios/generation.toml");
            let meta = fs::read_to_string(path)
                .ok()
                .and_then(|text| GenerationMeta::from_toml(&text).ok());
            let mut states = Vec::new();
            if state.booted == Some(gen) {
                states.push("booted");
            }
            if state.default_gen() == Some(gen) {
                states.push("default");
            }
            if bad.contains(&gen) {
                states.push("bad");
            }
            let unknown = || "?".to_string();
            GenRow {
                gen,
                created: meta.as_ref().map_or_else(unknown, |m| m.created.clone()),
                commit: meta
                    .as_ref()
                    .map_or_else(unknown, |m| m.manifest_commit.clone()),
                kernels: meta.map(|m| m.kernels).unwrap_or_default(),
                states,
            }
        })
        .collect())
}

/// The `aios gen list` table.
pub fn render_gen_list(rows: &[GenRow]) -> String {
    let mut out = format!(
        "{:<4}  {:<20}  {:<7}  {:<14}  KERNELS\n",
        "GEN", "CREATED", "COMMIT", "STATE"
    );
    for row in rows {
        let states = if row.states.is_empty() {
            "-".to_string()
        } else {
            row.states.join(",")
        };
        out.push_str(&format!(
            "{:<4}  {:<20}  {:<7}  {:<14}  {}\n",
            row.gen.to_string(),
            row.created,
            row.commit,
            states,
            row.kernels.join(", ")
        ));
    }
    out
}
