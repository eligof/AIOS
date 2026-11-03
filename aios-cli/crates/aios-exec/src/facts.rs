use crate::{ExecError, Layout};
use aios_gen::GenId;
use aios_manifest::Manifest;
use aios_render::RenderCtx;
use std::collections::BTreeMap;
use std::fs;

/// Machine facts the renderers need beyond the manifest. The CLI gathers them; apply and
/// plan only read them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineFacts {
    /// Content of `/usr/lib/aios/cmdline-hardening`.
    pub hardening_cmdline: String,
    /// UUID of the LUKS2 partition (`rd.luks.name=<uuid>=aios`).
    pub luks_uuid: String,
    /// Volume id of the ESP (`findmnt -no UUID <esp>`).
    pub esp_uuid: String,
}

impl MachineFacts {
    /// The validated render context for generation `gen` (`RenderCtx::new`).
    pub fn render_ctx(&self, gen: GenId) -> Result<RenderCtx, ExecError> {
        RenderCtx::new(
            gen,
            &self.luks_uuid,
            &self.esp_uuid,
            &self.hardening_cmdline,
        )
        .map_err(ExecError)
    }
}

/// `secrets/passwd/<user>` for every declared user, trailing newlines trimmed.
pub fn read_hashes(layout: &Layout, m: &Manifest) -> Result<BTreeMap<String, String>, ExecError> {
    let mut hashes = BTreeMap::new();
    for user in m.users.keys() {
        let path = layout.passwd_secret(user);
        let text = fs::read_to_string(&path).map_err(|e| ExecError::io(&path, e))?;
        hashes.insert(user.clone(), text.trim_end_matches('\n').to_string());
    }
    Ok(hashes)
}
